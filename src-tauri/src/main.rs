#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use flume::RecvTimeoutError as FlumeRecvTimeoutError;
use hex;
use local_ip_address::local_ip;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use reqwest::{blocking::Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/google.polo.wire.protobuf.rs"));

mod remotemessage {
    include!(concat!(env!("OUT_DIR"), "/remote.rs"));
}

use outer_message::Status;
use prost::Message;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::{certs as parse_pem_certs, pkcs8_private_keys};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::{client::TlsStream, rustls, TlsConnector};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

#[derive(Debug)]
struct NoVerifier;

const ANDROID_TV_SERVICE_TYPE: &str = "_androidtvremote2._tcp";
const ANDROID_TV_SERVICE_TYPE_LOCAL: &str = "_androidtvremote2._tcp.local.";
const ANDROID_TV_PAIRING_SERVICE_NAME: &str = "androidtvremote2";
const ANDROID_TV_CLIENT_NAME: &str = "MyTVRemote";

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn generate_cert() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| e.to_string())?;
    let key_der = private_key.to_pkcs8_der().map_err(|e| e.to_string())?;

    let key_pair = rcgen::KeyPair::from_der(key_der.as_bytes()).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![ANDROID_TV_CLIENT_NAME.to_string()]);
    params.alg = &rcgen::PKCS_RSA_SHA256;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params).map_err(|e| e.to_string())?;
    let cert_pem = cert.serialize_pem().map_err(|e| e.to_string())?;
    let key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;

    Ok((cert_pem, key_pem.to_string()))
}

type AndroidTlsStream = TlsStream<TokioTcpStream>;

async fn send_outer_message(
    stream: &mut AndroidTlsStream,
    message: &OuterMessage,
) -> Result<(), String> {
    let mut payload = Vec::new();
    message.encode(&mut payload).map_err(|e| e.to_string())?;
    let prefix = encode_varint(payload.len() as u64);
    stream
        .write_all(&prefix)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn send_remote_message(
    stream: &mut AndroidTlsStream,
    message: &remotemessage::RemoteMessage,
) -> Result<usize, String> {
    let mut payload = Vec::new();
    message.encode(&mut payload).map_err(|e| e.to_string())?;
    let prefix = encode_varint(payload.len() as u64);
    stream
        .write_all(&prefix)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(payload.len())
}

async fn read_outer_message(stream: &mut AndroidTlsStream) -> Result<OuterMessage, String> {
    let frame_len = read_varint(stream).await? as usize;
    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|e| e.to_string())?;
    OuterMessage::decode(&frame[..]).map_err(|e| e.to_string())
}

async fn try_read_remote_message(stream: &mut AndroidTlsStream) -> Result<Option<remotemessage::RemoteMessage>, String> {
    match tokio::time::timeout(Duration::from_millis(100), read_varint(stream)).await {
        Ok(Ok(frame_len)) => {
            let frame_len = frame_len as usize;
            let mut frame = vec![0u8; frame_len];
            stream
                .read_exact(&mut frame)
                .await
                .map_err(|e| e.to_string())?;
            let msg = remotemessage::RemoteMessage::decode(&frame[..]).map_err(|e| e.to_string())?;
            Ok(Some(msg))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None), // Timeout, no message
    }
}

async fn read_remote_message(stream: &mut AndroidTlsStream) -> Result<remotemessage::RemoteMessage, String> {
    let frame_len = read_varint(stream).await? as usize;
    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|e| e.to_string())?;
    remotemessage::RemoteMessage::decode(&frame[..]).map_err(|e| e.to_string())
}

async fn handle_remote_message(
    msg: &remotemessage::RemoteMessage,
    stream: &mut AndroidTlsStream,
) -> Result<bool, String> {
    const ACTIVE_FEATURES: i32 = 611; // PING | KEY | POWER | VOLUME | APP_LINK
    println!("[handle_remote_message] Full message: {:?}", msg);
    let mut response: Option<remotemessage::RemoteMessage> = None;
    let mut remote_started = false;

    // Handle based on which field is set (TV might not set message_type correctly)
    if let Some(set_active) = &msg.remote_set_active {
        println!("[handle_remote_message] TV wants active features: {}", set_active.active);
        println!("[handle_remote_message] Advertising active features: {}", ACTIVE_FEATURES);
        response = Some(remotemessage::RemoteMessage {
            remote_set_active: Some(remotemessage::RemoteSetActive { active: ACTIVE_FEATURES }),
            ..Default::default()
        });
    } else if let Some(ping) = &msg.remote_ping_request {
        println!(
            "[handle_remote_message] Responding to ping with val1={}, val2={}",
            ping.val1, ping.val2
        );
        response = Some(remotemessage::RemoteMessage {
            remote_ping_response: Some(remotemessage::RemotePingResponse { val1: ping.val1 }),
            ..Default::default()
        });
    } else if let Some(configure) = &msg.remote_configure {
        println!("[handle_remote_message] Responding to RemoteConfigure from TV");
        println!("[handle_remote_message] TV features: {}", configure.code1);
        response = Some(remotemessage::RemoteMessage {
            remote_configure: Some(remotemessage::RemoteConfigure {
                code1: ACTIVE_FEATURES,
                device_info: Some(remotemessage::RemoteDeviceInfo {
                    model: "".to_string(),
                    vendor: "".to_string(),
                    unknown1: 1,
                    unknown2: "1".to_string(),
                    package_name: "atvremote".to_string(),
                    app_version: "1.0.0".to_string(),
                }),
            }),
            ..Default::default()
        });
    } else if let Some(start) = &msg.remote_start {
        println!("[handle_remote_message] Received RemoteStart from TV: started={}", start.started);
        remote_started = start.started;
    } else {
        println!("[handle_remote_message] Unhandled message");
    }

    if let Some(resp) = response {
        let bytes = send_remote_message(stream, &resp).await?;
        println!("[handle_remote_message] Sent response ({} bytes)", bytes);
    }

    Ok(remote_started)
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
    buf
}

async fn read_varint(stream: &mut AndroidTlsStream) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for _ in 0..10 {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        let value = (byte[0] & 0x7F) as u64;
        result |= value << shift;
        if (byte[0] & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err("Varint length prefix is too long".to_string())
}

fn rsa_components_from_pem(pem_str: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (_, pem) = parse_x509_pem(pem_str.as_bytes()).map_err(|e| e.to_string())?;
    let cert = pem.parse_x509().map_err(|e| e.to_string())?;
    rsa_components_from_cert(&cert)
}

fn rsa_components_from_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    rsa_components_from_cert(&cert)
}

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    bytes.iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect()
}

fn rsa_components_from_cert<'a>(cert: &X509Certificate<'a>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let parsed = cert.public_key().parsed().map_err(|e| e.to_string())?;

    if let PublicKey::RSA(rsa_key) = parsed {
        let modulus = strip_leading_zeros(rsa_key.modulus);
        let exponent = strip_leading_zeros(rsa_key.exponent);
        Ok((modulus, exponent))
    } else {
        Err("Certificate public key is not RSA".to_string())
    }
}

#[tauri::command]
async fn start_pairing(ip: String) -> Result<PairingStartResult, String> {
    let trimmed_ip = ip.trim();
    if trimmed_ip.is_empty() {
        return Err("TV IP address is required to start pairing.".to_string());
    }

    let ip = trimmed_ip.to_string();
    println!("[start_pairing] Initiating pairing handshake with {}", ip);

    let (cert_pem, key_pem) = generate_cert()?;

    let mut cert_cursor = Cursor::new(cert_pem.as_bytes());
    let certs = parse_pem_certs(&mut cert_cursor)
        .map_err(|_| "Failed to parse generated client certificate.".to_string())?
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect::<Vec<_>>();

    let mut key_cursor = Cursor::new(key_pem.as_bytes());
    let mut keys = pkcs8_private_keys(&mut key_cursor)
        .map_err(|_| "Failed to parse generated client key.".to_string())?;
    let key_bytes = keys
        .pop()
        .ok_or_else(|| "Generated key missing PKCS#8 data.".to_string())?;
    let key = PrivateKeyDer::Pkcs8(key_bytes.into());

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_client_auth_cert(certs, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols.push(b"remote_pairing".to_vec());
    let connector = TlsConnector::from(Arc::new(config));

    // Connect
    let stream = TokioTcpStream::connect(format!("{}:6467", ip))
        .await
        .map_err(|e| e.to_string())?;
    let ip_addr: std::net::IpAddr = ip.parse().map_err(|_| "Invalid IP address".to_string())?;
    let domain = rustls::pki_types::ServerName::IpAddress(ip_addr.into());
    let mut tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| e.to_string())?;
    println!("[start_pairing] TLS session established with {}", ip);

    // Begin pairing handshake following Android TV protocol.
    println!(
        "[start_pairing] Sending PairingRequest (service={}, client={})",
        ANDROID_TV_PAIRING_SERVICE_NAME, ANDROID_TV_CLIENT_NAME
    );
    let request = OuterMessage {
        protocol_version: 2,
        status: Status::Ok as i32,
        pairing_request: Some(PairingRequest {
            service_name: ANDROID_TV_PAIRING_SERVICE_NAME.to_string(),
            client_name: ANDROID_TV_CLIENT_NAME.to_string(),
        }),
        ..Default::default()
    };
    send_outer_message(&mut tls_stream, &request).await?;

    loop {
        let incoming = match tokio::time::timeout(
            Duration::from_secs(10),
            read_outer_message(&mut tls_stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(
                    "Timed out waiting for pairing response from Android TV.".to_string(),
                )
            }
        };
        println!("[start_pairing] Incoming message: {:?}", incoming);
        println!(
            "[start_pairing] Received message: status={}, has_ack={}, has_options={}, has_config_ack={}, has_secret_ack={}",
            incoming.status,
            incoming.pairing_request_ack.is_some(),
            incoming.options.is_some(),
            incoming.configuration_ack.is_some(),
            incoming.secret_ack.is_some()
        );
        if incoming.status != Status::Ok as i32 {
            return Err(format!("Pairing failed with status {}", incoming.status));
        }

        if incoming.pairing_request_ack.is_some() {
            println!("[start_pairing] Received PairingRequestAck from {}", ip);
            println!("[start_pairing] Sending Options to {}", ip);
            let options_msg = OuterMessage {
                protocol_version: 2,
                status: Status::Ok as i32,
                options: Some(Options {
                    input_encodings: vec![options::Encoding {
                        r#type: options::encoding::EncodingType::Hexadecimal as i32,
                        symbol_length: 6,
                    }],
                    output_encodings: Vec::new(),
                    preferred_role: options::RoleType::Input as i32,
                }),
                ..Default::default()
            };
            send_outer_message(&mut tls_stream, &options_msg).await?;
        } else if incoming.options.is_some() {
            println!("[start_pairing] Received Options from {}", ip);
            println!("[start_pairing] Sending Configuration to {}", ip);
            let configuration_msg = OuterMessage {
                protocol_version: 2,
                status: Status::Ok as i32,
                configuration: Some(Configuration {
                    encoding: Some(options::Encoding {
                        r#type: options::encoding::EncodingType::Hexadecimal as i32,
                        symbol_length: 6,
                    }),
                    client_role: options::RoleType::Input as i32,
                }),
                ..Default::default()
            };
            send_outer_message(&mut tls_stream, &configuration_msg).await?;
        } else if incoming.configuration_ack.is_some() {
            println!(
                "[start_pairing] Configuration acknowledged by {}. Waiting for PIN entry.",
                ip
            );
            break;
        } else {
            println!(
                "[start_pairing] Unexpected pairing message from {}. Continuing to wait...",
                ip
            );
        }
    }

    let server_cert_der = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first().cloned())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| "Unable to retrieve server certificate from Android TV.".to_string())?;

    {
        let mut sessions = PAIRING_SESSIONS.lock().unwrap();
        sessions.insert(
            ip.clone(),
            PairingSession {
                client_id: "androidtv".to_string(),
                user_id: None,
                tls_stream: Some(tls_stream),
                client_cert_pem: cert_pem,
                client_key_pem: key_pem,
                server_cert_der,
                remote_started: false,
                remote_stream: None,  // Will be initialized when first key is sent
            },
        );
    }

    Ok(PairingStartResult {
        client_id: "androidtv".to_string(),
        transport: "SSL".to_string(),
        status: "pin_displayed".to_string(),
        message: "Android TV pairing initiated. Enter the PIN shown on the TV.".to_string(),
    })
}

#[tauri::command]
async fn complete_pairing(ip: String, pin: String) -> Result<PairingCompleteResult, String> {
    let trimmed_ip = ip.trim();
    if trimmed_ip.is_empty() {
        return Err("TV IP address is required to complete pairing.".to_string());
    }

    let trimmed_pin = pin.trim();
    if trimmed_pin.is_empty() {
        return Err("Enter the PIN shown on the TV to complete pairing.".to_string());
    }

    let ip = trimmed_ip.to_string();
    let pin_code = trimmed_pin.to_ascii_uppercase();
    println!(
        "[complete_pairing] Completing pairing for {} with provided PIN",
        ip
    );

    if pin_code.len() != 6 || !pin_code.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("PIN must be a 6-digit hexadecimal value.".to_string());
    }

    let (mut session, mut tls_stream) = {
        let mut sessions = PAIRING_SESSIONS.lock().unwrap();
        let mut session = sessions
            .remove(&ip)
            .ok_or_else(|| "Start pairing before attempting to complete it.".to_string())?;
        let stream = session.tls_stream.take().ok_or_else(|| {
            "Pairing session is no longer active. Start pairing again.".to_string()
        })?;
        (session, stream)
    };

    let client_id = session.client_id.clone();

    let (client_modulus, client_exponent) = rsa_components_from_pem(&session.client_cert_pem)?;
    let (server_modulus, server_exponent) = rsa_components_from_der(&session.server_cert_der)?;

    println!("[complete_pairing] Client Modulus: {} bytes", client_modulus.len());
    println!("[complete_pairing] Client Exponent: {} bytes", client_exponent.len());
    println!("[complete_pairing] Server Modulus: {} bytes", server_modulus.len());
    println!("[complete_pairing] Server Exponent: {} bytes", server_exponent.len());

    let prefix_value = u8::from_str_radix(&pin_code[..2], 16)
        .map_err(|_| "Failed to parse PIN checksum.".to_string())?;
    let suffix_bytes = hex::decode(&pin_code[2..])
        .map_err(|_| "PIN must be a valid hexadecimal string.".to_string())?;

    println!("[complete_pairing] PIN Suffix: {:x?}", suffix_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&client_modulus);
    hasher.update(&client_exponent);
    hasher.update(&server_modulus);
    hasher.update(&server_exponent);
    hasher.update(&suffix_bytes);
    let secret = hasher.finalize();

    println!("[complete_pairing] Computed Secret: {:x?}", secret);
    println!("[complete_pairing] PIN Prefix: {:x}", prefix_value);

    if secret[0] != prefix_value {
        return Err(
            "PIN verification failed. Make sure you entered the code shown on the TV.".to_string(),
        );
    }

    let secret_msg = OuterMessage {
        protocol_version: 2,
        status: Status::Ok as i32,
        secret: Some(Secret {
            secret: secret.to_vec(),
        }),
        ..Default::default()
    };
    println!("[complete_pairing] Sending Secret message to {}", ip);
    send_outer_message(&mut tls_stream, &secret_msg).await?;

    loop {
        let response = match tokio::time::timeout(
            Duration::from_secs(10),
            read_outer_message(&mut tls_stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(
                    "Timed out waiting for final pairing confirmation from Android TV.".to_string(),
                )
            }
        };
        println!(
            "[complete_pairing] Received message: status={}, has_secret_ack={}",
            response.status,
            response.secret_ack.is_some()
        );
        if response.status != Status::Ok as i32 {
            let status = Status::try_from(response.status).unwrap_or(Status::Error);
            return Err(match status {
                Status::BadSecret => "PIN verification failed on TV. Re-enter the displayed code.".to_string(),
                Status::BadConfiguration => "TV rejected configuration; restart pairing on the TV and try again.".to_string(),
                Status::Error => "TV reported an unspecified error while completing pairing.".to_string(),
                _ => format!("Pairing secret rejected with status {}", response.status),
            });
        }

        if response.secret_ack.is_some() {
            println!("[complete_pairing] Secret acknowledged by {}", ip);
            break;
        }
    }

    session.tls_stream = Some(tls_stream);
    {
        let mut sessions = PAIRING_SESSIONS.lock().unwrap();
        sessions.insert(ip.clone(), session);
    }

    Ok(PairingCompleteResult {
        client_id,
        user_id: None,
        transport: "SSL".to_string(),
        status: "paired".to_string(),
        message: "Pairing complete. Secure channel established with Android TV.".to_string(),
    })
}

#[tauri::command]
async fn send_remote_key(ip: String, key_code: String) -> Result<String, String> {
    let trimmed_ip = ip.trim();
    if trimmed_ip.is_empty() {
        return Err("TV IP address is required to send remote key.".to_string());
    }

    let ip = trimmed_ip.to_string();
    println!("[send_remote_key] Sending {} to {}", key_code, ip);

    // Get certificates from pairing session
    let (client_cert_pem, client_key_pem, mut remote_started, existing_stream) = {
        let mut sessions = PAIRING_SESSIONS.lock().unwrap();
        let session = sessions
            .get_mut(&ip)
            .ok_or_else(|| "No active pairing session. Complete pairing first.".to_string())?;
        (
            session.client_cert_pem.clone(),
            session.client_key_pem.clone(),
            session.remote_started,
            session.remote_stream.take(),  // Use remote_stream instead of tls_stream
        )
    };

    // Create or use existing remote control TLS connection on port 6466
    let mut tls_stream = if let Some(stream) = existing_stream {
        stream
    } else {
        // Create new connection on port 6466 for remote control
        println!("[send_remote_key] Creating new remote control connection to {}:6466", ip);
        
        let stream = TokioTcpStream::connect(format!("{}:6466", ip))
            .await
            .map_err(|e| format!("Failed to connect to TV on port 6466: {}", e))?;

        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_client_auth_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    parse_pem_certs(&mut Cursor::new(client_cert_pem.as_bytes()))
                        .map_err(|e| format!("Failed to parse client cert: {}", e))?
                        .into_iter()
                        .next()
                        .ok_or("No certificate found in PEM")?
                )],
                PrivateKeyDer::Pkcs8(
                    pkcs8_private_keys(&mut Cursor::new(client_key_pem.as_bytes()))
                        .map_err(|e| format!("Failed to parse private keys: {}", e))?
                        .into_iter()
                        .next()
                        .ok_or("No private key found")?
                        .into()
                ),
            )
            .map_err(|e| format!("Failed to configure client auth: {}", e))?;
        
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_config));
        let domain = rustls::pki_types::ServerName::try_from("Google")
            .map_err(|e| format!("Invalid server name: {}", e))?
            .to_owned();

        connector
            .connect(domain, stream)
            .await
            .map_err(|e| format!("TLS handshake failed on port 6466: {}", e))?
    };

    // Handle any pending messages already in the socket buffer
    while let Ok(Some(msg)) = try_read_remote_message(&mut tls_stream).await {
        println!("[send_remote_key] Handling pending message from TV: {:?}", msg);
        if handle_remote_message(&msg, &mut tls_stream).await? {
            println!("[send_remote_key] TV already marked remote session as started");
            remote_started = true;
        }
    }

    if !remote_started {
        println!(
            "[send_remote_key] Waiting for TV to complete remote handshake (RemoteConfigure/RemoteStart)"
        );

        for attempt in 0..5 {
            if remote_started {
                break;
            }

            match tokio::time::timeout(Duration::from_millis(1200), read_remote_message(&mut tls_stream)).await {
                Ok(Ok(tv_msg)) => {
                    println!("[send_remote_key] Received handshake message from TV: {:?}", tv_msg);
                    if handle_remote_message(&tv_msg, &mut tls_stream).await? {
                        println!("[send_remote_key] TV signaled RemoteStart; ready to send keys");
                        remote_started = true;
                        break;
                    }
                }
                Ok(Err(e)) => {
                    println!("[send_remote_key] Error reading TV handshake message: {}", e);
                    break;
                }
                Err(_) => {
                    println!("[send_remote_key] Handshake wait attempt {} timed out", attempt + 1);
                }
            }
        }

        if !remote_started {
            println!("[send_remote_key] Warning: TV has not sent RemoteStart; key may not have effect yet");
        }
    }

    let key_code_value = match key_code.as_str() {
        "KEYCODE_DPAD_UP" => remotemessage::remote_key_inject::KeyCode::KeycodeDpadUp as i32,
        "KEYCODE_DPAD_DOWN" => remotemessage::remote_key_inject::KeyCode::KeycodeDpadDown as i32,
        "KEYCODE_DPAD_LEFT" => remotemessage::remote_key_inject::KeyCode::KeycodeDpadLeft as i32,
        "KEYCODE_DPAD_RIGHT" => remotemessage::remote_key_inject::KeyCode::KeycodeDpadRight as i32,
        "KEYCODE_DPAD_CENTER" => remotemessage::remote_key_inject::KeyCode::KeycodeDpadCenter as i32,
        "KEYCODE_VOLUME_UP" => remotemessage::remote_key_inject::KeyCode::KeycodeVolumeUp as i32,
        "KEYCODE_VOLUME_DOWN" => remotemessage::remote_key_inject::KeyCode::KeycodeVolumeDown as i32,
        "KEYCODE_POWER" => remotemessage::remote_key_inject::KeyCode::KeycodePower as i32,
        "KEYCODE_BACK" => remotemessage::remote_key_inject::KeyCode::KeycodeBack as i32,
        "KEYCODE_HOME" => remotemessage::remote_key_inject::KeyCode::KeycodeHome as i32,
        "KEYCODE_MENU" => remotemessage::remote_key_inject::KeyCode::KeycodeMenu as i32,
        "KEYCODE_VOLUME_MUTE" => remotemessage::remote_key_inject::KeyCode::KeycodeVolumeMute as i32,
        _ => return Err(format!("Unknown key code: {}", key_code)),
    };

    let key_inject = remotemessage::RemoteKeyInject {
        key_code: key_code_value,
        direction: remotemessage::remote_key_inject::Direction::Short as i32,
    };

    let remote_msg = remotemessage::RemoteMessage {
        remote_key_inject: Some(key_inject),
        ..Default::default()
    };

    let payload_len = send_remote_message(&mut tls_stream, &remote_msg).await?;
    println!(
        "[send_remote_key] Sent key {} ({} bytes, started={})",
        key_code, payload_len, remote_started
    );

    // Try to read any immediate responses
    while let Ok(Some(msg)) = try_read_remote_message(&mut tls_stream).await {
        println!("[send_remote_key] Received response message from TV: {:?}", msg);
        if handle_remote_message(&msg, &mut tls_stream).await? {
            remote_started = true;
        }
    }

    {
        let mut sessions = PAIRING_SESSIONS.lock().unwrap();
        if let Some(session) = sessions.get_mut(&ip) {
            session.remote_started = remote_started;
            session.remote_stream = Some(tls_stream);  // Store in remote_stream
        }
    }

    Ok(format!("Sent {} to {}", key_code, ip))
}

#[tauri::command]
fn test_connection(ip: String) -> Result<String, String> {
    let trimmed_ip = ip.trim();
    if trimmed_ip.is_empty() {
        return Err("Enter the TV IP address first.".to_string());
    }

    println!(
        "[test_connection] Testing Sony TV connectivity for {}",
        trimmed_ip
    );

    let psk: Option<String> = None;
    let pin: Option<String> = None;

    match test_tv_connection(trimmed_ip, &psk, &pin) {
        TestOutcome::Reachable { transport } => Ok(format!(
            "Sony TV at {} responded via {}.",
            trimmed_ip,
            transport.label()
        )),
        TestOutcome::AuthRequired { status, transport } => Err(format!(
            "Sony TV at {} requires authentication (HTTP {} via {}). Provide PSK or PIN and try again.",
            trimmed_ip,
            status,
            transport.label()
        )),
        TestOutcome::NoResponse => Err(format!(
            "No response from {}. Verify the IP address, network connectivity, and that the TV is powered on.",
            trimmed_ip
        )),
    }
}

#[tauri::command]
fn send_ircc(
    ip: String,
    code: String,
    psk: Option<String>,
    pin: Option<String>,
) -> Result<String, String> {
    println!(
        "[send_ircc] Starting IRCC command request to {} with code: {}",
        ip, code
    );

    let trimmed_psk = psk.unwrap_or_default().trim().to_string();
    let trimmed_pin = pin.unwrap_or_default().trim().to_string();

    // Detailed pairing authentication logging
    if !trimmed_psk.is_empty() {
        println!(
            "[send_ircc] Using Pre-Shared Key (PSK) authentication for TV at {}",
            ip
        );
        println!("[send_ircc] PSK length: {} characters", trimmed_psk.len());
    } else {
        println!("[send_ircc] No Pre-Shared Key (PSK) provided - TV may reject request");
    }

    if !trimmed_pin.is_empty() {
        println!("[send_ircc] Using PIN authentication for TV at {}", ip);
        println!("[send_ircc] PIN length: {} characters", trimmed_pin.len());
    } else {
        println!("[send_ircc] No PIN provided - TV may reject request");
    }

    if trimmed_psk.is_empty() && trimmed_pin.is_empty() {
        println!("[send_ircc] WARNING: No authentication credentials provided. TV likely requires PSK or PIN pairing.");
        println!("[send_ircc] To pair with TV: Go to TV Settings > Network > Remote Start > Pre-Shared Key or PIN");
    }

    let body = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>{}</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#,
        code
    );
    println!(
        "[send_ircc] SOAP request body prepared with IRCC code: {}",
        code
    );

    let client = build_client(5).map_err(|e| {
        println!("[send_ircc] Failed to build HTTP client: {}", e);
        format!("Failed to build HTTP client: {}", e)
    })?;

    let mut last_error: Option<String> = None;
    let transports = [
        Transport::Http,
        Transport::Https,
        Transport::Http6466,
        Transport::Https6466,
    ];

    println!(
        "[send_ircc] Attempting connection via {} transport methods",
        transports.len()
    );

    for transport in transports {
        println!(
            "[send_ircc] Attempting IRCC request via {} ({})",
            transport.label(),
            transport.url(&ip)
        );

        match perform_ircc_request(&client, &ip, &body, &trimmed_psk, &trimmed_pin, transport) {
            Ok(status) => {
                println!(
                    "[send_ircc] Transport {} returned HTTP status: {}",
                    transport.label(),
                    status
                );

                if status.is_success() {
                    let via = transport.label();
                    println!(
                        "[send_ircc] SUCCESS: Command sent successfully via {} to TV at {}",
                        via, ip
                    );
                    return Ok(format!("Command sent successfully via {}", via));
                } else if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    let via = transport.label();
                    println!(
                        "[send_ircc] AUTHENTICATION FAILED: TV rejected command (HTTP {}) via {}",
                        status.as_u16(),
                        via
                    );
                    println!("[send_ircc] This indicates pairing/authentication issue:");
                    println!("[send_ircc] - Ensure PSK matches TV's Pre-Shared Key setting");
                    println!("[send_ircc] - Or complete PIN pairing process on TV");
                    println!("[send_ircc] - Check TV Settings > Network > Remote Start");
                    return Err(format!("TV rejected the command (HTTP {}) via {}. Ensure the Pre-Shared Key matches the one configured on the TV or complete PIN pairing.", status.as_u16(), via));
                } else if matches!(transport, Transport::Http | Transport::Http6466) {
                    let retry_transport = if transport == Transport::Http {
                        Transport::Https
                    } else {
                        Transport::Https6466
                    };
                    println!(
                        "[send_ircc] {} responded with HTTP {} over {}; retrying with {} (upgrading to secure transport)",
                        ip, status, transport.label(), retry_transport.label()
                    );
                    last_error = Some(format!("HTTP {}", status));
                    continue;
                } else {
                    println!(
                        "[send_ircc] FAILED: Command failed via {} with HTTP {}",
                        transport.label(),
                        status
                    );
                    return Err(format!(
                        "Failed to send command via {}: HTTP {}",
                        transport.label(),
                        status
                    ));
                }
            }
            Err(err) => {
                println!(
                    "[send_ircc] CONNECTION ERROR: {} request over {} failed: {}",
                    ip,
                    transport.label(),
                    err
                );
                last_error = Some(err.to_string());
                continue;
            }
        }
    }

    let final_error =
        last_error.unwrap_or_else(|| "Unable to reach TV over HTTP or HTTPS.".to_string());
    println!("[send_ircc] ALL TRANSPORTS FAILED: {}", final_error);
    Err(final_error)
}

#[tauri::command]
fn cast_launch_app(ip: String, app_name: String) -> Result<String, String> {
    println!(
        "[cast_launch_app] Starting app launch for '{}' on TV at {}",
        app_name, ip
    );

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let url = if app_name == "Netflix" {
        format!("http://{}:8008/apps/{}", ip, app_name)
    } else {
        format!("https://{}:8443/apps/{}", ip, app_name)
    };
    println!("[cast_launch_app] Using URL: {}", url);

    let response = client.post(&url).send().map_err(|e| {
        println!("[cast_launch_app] Request failed: {}", e);
        format!("Failed to send request to {}: {}", url, e)
    })?;

    let status = response.status();
    println!("[cast_launch_app] Response status: {}", status);

    if status == StatusCode::CREATED || status == StatusCode::OK {
        println!("[cast_launch_app] Launch successful");
        Ok(format!(
            "Successfully launched {} on TV at {}",
            app_name, ip
        ))
    } else if status == StatusCode::NOT_FOUND {
        println!("[cast_launch_app] App not found via this protocol");
        Err(format!(
            "App '{}' not available via this protocol on TV at {}",
            app_name, ip
        ))
    } else {
        println!("[cast_launch_app] Launch failed with status {}", status);
        Err(format!("Failed to launch {}: HTTP {}", app_name, status))
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Device {
    ip: String,
    name: Option<String>,
    service: Option<String>,
    status: String,
    mac: Option<String>,
    vendor: Option<String>,
    ports: Option<Vec<u16>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct MdnsRecord {
    service: String,
    fullname: String,
    hostname: Option<String>,
    port: u16,
    ips: Vec<String>,
    txt: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ScanResult {
    mdns_devices: Vec<Device>,
    mdns_raw_records: Vec<MdnsRecord>,
    ssdp_devices: Vec<Device>,
    arp_devices: Vec<Device>,
    sony_tvs: Vec<String>,
    logs: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Http,
    Https,
    Http6466,
    Https6466,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Transport::Http => "HTTP",
            Transport::Https => "HTTPS",
            Transport::Http6466 => "HTTP:6466",
            Transport::Https6466 => "HTTPS:6466",
        }
    }

    fn url(self, ip: &str) -> String {
        match self {
            Transport::Http => format!("http://{}/sony/IRCC", ip),
            Transport::Https => format!("https://{}/sony/IRCC", ip),
            Transport::Http6466 => format!("http://{}:6466/sony/IRCC", ip),
            Transport::Https6466 => format!("https://{}:6466/sony/IRCC", ip),
        }
    }
}

static OUI_PREFIXES: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    HashMap::from([
        ("00:19:C5", "Sony"),
        ("00:1F:A7", "Sony"),
        ("28:39:26", "Sony"),
        ("3C:07:54", "Sony"),
        ("54:EE:75", "Sony"),
        ("B8:78:2E", "Sony"),
        ("F0:1D:BC", "Sony"),
        ("F4:5C:89", "Sony"),
        ("FC:C2:DE", "Sony"),
        ("44:65:0D", "Amazon"),
        ("74:C2:46", "Amazon"),
        ("88:F0:77", "Amazon"),
        ("F4:0E:22", "Amazon"),
        ("A4:5E:60", "Apple"),
        ("D4:C1:C8", "Apple"),
        ("E0:AC:CB", "Apple"),
        ("F0:27:65", "Apple"),
        ("58:40:4E", "Apple"),
        ("DC:A6:32", "Samsung"),
        ("F4:0F:24", "Samsung"),
        ("78:8A:20", "LG"),
        ("C8:14:79", "LG"),
        ("D8:F2:CA", "Google"),
        ("B4:F3:F4", "Google"),
        ("7C:2E:0D", "Google"),
        ("B8:27:EB", "Raspberry Pi"),
        ("AC:67:B2", "Xiaomi"),
        ("64:16:66", "Xiaomi"),
    ])
});

static DEFAULT_PORT_SCAN_PORTS: &[u16] = &[
    80,   // HTTP control endpoints
    443,  // HTTPS control endpoints
    502,  // Modbus / proprietary control
    523,  // Sony Scalar Web API
    554,  // RTSP streaming
    5555, // Android debug/remote bridge
    6466, // Android TV Remote (TLS)
    6467, // Android TV Remote (plain)
    7001, // AirPlay
    8008, // Chromecast HTTP
    8009, // Chromecast HTTPS
    8443, // Alternate HTTPS
    9000, // UPnP/DLNA services
];

struct PairingSession {
    client_id: String,
    user_id: Option<String>,
    tls_stream: Option<AndroidTlsStream>,
    client_cert_pem: String,
    client_key_pem: String,
    server_cert_der: Vec<u8>,
    remote_started: bool,
    remote_stream: Option<AndroidTlsStream>,  // Persistent connection for remote control
}

static PAIRING_SESSIONS: Lazy<Mutex<HashMap<String, PairingSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Serialize)]
struct PairingStartResult {
    client_id: String,
    transport: String,
    status: String,
    message: String,
}

#[derive(Serialize)]
struct PairingCompleteResult {
    client_id: String,
    user_id: Option<String>,
    transport: String,
    status: String,
    message: String,
}

fn normalize_mac(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("(incomplete)") {
        return None;
    }

    let cleaned = trimmed.replace('-', ":").to_uppercase();
    let parts: Vec<String> = cleaned
        .split(':')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut seg = segment.to_string();
            if seg.len() == 1 {
                seg.insert(0, '0');
            }
            seg
        })
        .collect();

    if parts.len() != 6 {
        return None;
    }

    if parts
        .iter()
        .any(|seg| seg.len() != 2 || !seg.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }

    Some(parts.join(":"))
}

fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let prefix = mac.split(':').take(3).collect::<Vec<_>>().join(":");
    OUI_PREFIXES.get(prefix.as_str()).copied()
}

fn should_scan_ip(ip: &str) -> bool {
    match ip.parse::<Ipv4Addr>() {
        Ok(addr) => {
            let octets = addr.octets();
            octets[3] != 0 && octets[3] != 255
        }
        Err(_) => false,
    }
}

fn scan_ports(ip: &str, timeout: Duration, ports: &[u16]) -> Vec<u16> {
    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return Vec::new(),
    };

    let mut open_ports: Vec<u16> = ports
        .par_iter()
        .filter_map(|port| {
            let socket = SocketAddr::new(ip_addr, *port);
            match TcpStream::connect_timeout(&socket, timeout) {
                Ok(_) => Some(*port),
                Err(_) => None,
            }
        })
        .collect();

    open_ports.sort_unstable();
    open_ports
}

enum TestOutcome {
    Reachable {
        transport: Transport,
    },
    AuthRequired {
        status: StatusCode,
        transport: Transport,
    },
    NoResponse,
}

fn record_mdns_service(
    info: &ServiceInfo,
    devices: &mut Vec<Device>,
    raw_records: &mut Vec<MdnsRecord>,
    seen_device_keys: &mut HashSet<String>,
    logs: &mut Vec<String>,
) {
    let fullname = info.get_fullname().to_string();
    let service_label = info.get_type().trim_end_matches(".local.");

    let hostname_str = info.get_hostname();
    let hostname = if hostname_str.is_empty() {
        None
    } else {
        Some(hostname_str.to_string())
    };
    let port = info.get_port();
    let mut ips: Vec<String> = info
        .get_addresses()
        .iter()
        .filter_map(|addr| match addr {
            IpAddr::V4(v4) => Some(v4.to_string()),
            IpAddr::V6(_) => None,
        })
        .collect();

    if ips.is_empty() {
        if let Some(ref host) = hostname {
            if let Ok(resolved) = (host.as_str(), 0u16).to_socket_addrs() {
                for addr in resolved {
                    if let IpAddr::V4(v4) = addr.ip() {
                        let ip_str = v4.to_string();
                        if !ips.contains(&ip_str) {
                            ips.push(ip_str);
                        }
                    }
                }
            }
        }
    }

    let txt_props: Vec<String> = info
        .get_properties()
        .iter()
        .map(|prop| {
            let key = prop.key();
            match prop.val() {
                Some(raw) if !raw.is_empty() => match std::str::from_utf8(raw) {
                    Ok(val) if !val.is_empty() => format!("{}={}", key, val),
                    Ok(_) => key.to_string(),
                    Err(_) => format!("{}=<{} bytes>", key, raw.len()),
                },
                _ => key.to_string(),
            }
        })
        .collect();

    raw_records.push(MdnsRecord {
        service: service_label.to_string(),
        fullname: fullname.clone(),
        hostname: hostname.clone(),
        port,
        ips: ips.clone(),
        txt: txt_props,
    });

    if ips.is_empty() {
        let msg = format!(
            "mDNS resolved {} but no IPv4 address was provided (hostname {:?})",
            fullname, hostname
        );
        logs.push(msg.clone());
        println!("[scan_network] {}", msg);
    } else {
        for ip_str in ips {
            let key = format!("{}|{}", service_label, ip_str);
            if seen_device_keys.insert(key) {
                let status = format!("mDNS service {} port {}", fullname, port);
                let msg = format!(
                    "mDNS found device at {} ({:?}) via {}:{}",
                    ip_str, hostname, service_label, port
                );
                devices.push(Device {
                    ip: ip_str.clone(),
                    name: hostname.clone(),
                    service: Some(service_label.to_string()),
                    status,
                    mac: None,
                    vendor: None,
                    ports: None,
                });
                logs.push(msg.clone());
                println!("[scan_network] {}", msg);
            }
        }
    }
}

fn discover_via_dns_sd(
    service_type: &str,
    devices: &mut Vec<Device>,
    raw_records: &mut Vec<MdnsRecord>,
    seen_device_keys: &mut HashSet<String>,
    logs: &mut Vec<String>,
) -> Result<(), String> {
    // Run dns-sd -B <service_type> with timeout
    let mut child = Command::new("dns-sd")
        .args(["-B", service_type])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn dns-sd -B: {}", e))?;

    thread::sleep(Duration::from_secs(10));

    if let Err(e) = child.kill() {
        logs.push(format!("Failed to kill dns-sd process: {}", e));
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to get dns-sd output: {}", e))?;

    if !output.status.success() && !output.status.code().map_or(true, |c| c == 9 || c == 143) {
        // Allow if killed by signal or SIGKILL/SIGTERM
        return Err(format!("dns-sd -B exited with status: {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    logs.push(format!("dns-sd -B output: {}", stdout));
    println!("[scan_network] dns-sd -B output: {}", stdout);

    // Parse output for instance names
    let mut instances = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 7 && parts[1] == "Add" {
            let instance = parts[6..].join(" ");
            instances.push(instance);
        }
    }

    for instance in instances {
        // Run dns-sd -L <instance> <service_type> with timeout
        let mut child = Command::new("dns-sd")
            .args(["-L", &instance, service_type])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn dns-sd -L for {}: {}", instance, e))?;

        thread::sleep(Duration::from_secs(5));

        if let Err(e) = child.kill() {
            logs.push(format!("Failed to kill dns-sd -L for {}: {}", instance, e));
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed to get dns-sd -L output for {}: {}", instance, e))?;

        if !output.status.success() && !output.status.code().map_or(true, |c| c == 9 || c == 143) {
            logs.push(format!(
                "dns-sd -L failed for {}: {}",
                instance, output.status
            ));
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut hostname = None;
        let mut port = 0;
        let mut txt = Vec::new();

        for line in stdout.lines() {
            if line.contains("can be reached at ") {
                let parts: Vec<&str> = line.split("can be reached at ").collect();
                if parts.len() >= 2 {
                    let addr_part = parts[1].split_whitespace().next().unwrap_or("");
                    let addr_parts: Vec<&str> = addr_part.split(':').collect();
                    if addr_parts.len() >= 2 {
                        hostname = Some(addr_parts[0].to_string());
                        if let Ok(p) = addr_parts[1].parse::<u16>() {
                            port = p;
                        }
                    }
                }
            } else if line.contains('=') && !line.contains("can be reached") {
                txt.push(line.to_string());
            }
        }

        if let Some(host) = hostname {
            // Resolve hostname to IP
            let ips = match (host.as_str(), port).to_socket_addrs() {
                Ok(addrs) => addrs
                    .filter_map(|addr| match addr {
                        SocketAddr::V4(v4) => Some(v4.ip().to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                Err(_) => {
                    logs.push(format!(
                        "Failed to resolve hostname {} for {}",
                        host, instance
                    ));
                    continue;
                }
            };

            if ips.is_empty() {
                logs.push(format!("No IPv4 addresses for {} ({})", instance, host));
                continue;
            }

            let fullname = format!("{}.{}", instance, service_type);
            let service_label = service_type.trim_end_matches('.').trim_start_matches('_');

            for ip_str in &ips {
                let key = format!("{}|{}", service_label, ip_str);
                if seen_device_keys.insert(key) {
                    let status = format!("dns-sd service {} port {}", fullname, port);
                    let msg = format!(
                        "dns-sd found device at {} ({}) via {}:{}",
                        ip_str, host, service_label, port
                    );
                    devices.push(Device {
                        ip: ip_str.clone(),
                        name: Some(host.clone()),
                        service: Some(service_label.to_string()),
                        status,
                        mac: None,
                        vendor: None,
                        ports: Some(vec![port]),
                    });
                    logs.push(msg.clone());
                    println!("[scan_network] {}", msg);
                }
            }

            raw_records.push(MdnsRecord {
                service: service_label.to_string(),
                fullname: fullname.clone(),
                hostname: Some(host),
                port,
                ips,
                txt,
            });
        }
    }

    Ok(())
}

fn discover_tvs_via_mdns(logs: &mut Vec<String>) -> (Vec<Device>, Vec<MdnsRecord>) {
    let mut devices: Vec<Device> = Vec::new();
    let mut raw_records: Vec<MdnsRecord> = Vec::new();
    let mut seen_device_keys: HashSet<String> = HashSet::new();
    let service_types = [
        "_sonyrc._tcp.local.",
        "_sonyremote._tcp.local.",
        "_sonybravia._tcp.local.",
        "_scalarwebapi._tcp.local.",
        "_ircc._tcp.local.",
        "_sonytv._tcp.local.",
        "_airplay._tcp.local.",
        "_googlecast._tcp.local.",
        "_raop._tcp.local.",
    ANDROID_TV_SERVICE_TYPE_LOCAL,
        "_companion-link._tcp.local.",
        "_mediaremotetv._tcp.local.",
        "_homekit._tcp.local.",
        "_servicediscovery._udp.local.",
        "_googlecast._udp.local.",
        "_ssh._tcp.local.",
        "_device-info._tcp.local.",
    ];

    let daemon = match ServiceDaemon::new() {
        Ok(daemon) => daemon,
        Err(err) => {
            let msg = format!("mDNS unavailable: {}", err);
            logs.push(msg.clone());
            println!("[scan_network] {}", msg);
            return (Vec::new(), Vec::new());
        }
    };

    let browse_window = Duration::from_secs(4);

    for service_type in service_types.iter() {
        logs.push(format!("Browsing mDNS service: {}", service_type));
        println!("[scan_network] Browsing mDNS service: {}", service_type);
        match daemon.browse(service_type) {
            Ok(receiver) => {
                let deadline = Instant::now() + browse_window;
                loop {
                    if Instant::now() >= deadline {
                        break;
                    }

                    match receiver.recv_timeout(Duration::from_millis(400)) {
                        Ok(event) => match event {
                            ServiceEvent::ServiceFound(service_type, fullname) => {
                                let msg = format!(
                                    "mDNS discovered candidate {} for {}",
                                    fullname, service_type
                                );
                                logs.push(msg.clone());
                                println!("[scan_network] {}", msg);
                            }
                            ServiceEvent::ServiceResolved(info) => {
                                record_mdns_service(
                                    &info,
                                    &mut devices,
                                    &mut raw_records,
                                    &mut seen_device_keys,
                                    logs,
                                );
                            }
                            ServiceEvent::ServiceRemoved(_, _) | ServiceEvent::SearchStopped(_) => {
                                break;
                            }
                            _ => {}
                        },
                        Err(FlumeRecvTimeoutError::Timeout) => {
                            continue;
                        }
                        Err(FlumeRecvTimeoutError::Disconnected) => {
                            break;
                        }
                    }
                }
            }
            Err(err) => {
                let msg = format!("mDNS browse failed for {}: {}", service_type, err);
                logs.push(msg.clone());
                println!("[scan_network] {}", msg);
            }
        }
    }

    // Fallback: if no mDNS devices found, try dns-sd for known Sony services
    if devices.is_empty() {
        logs.push("No devices found via mDNS; trying dns-sd fallback".to_string());
        println!("[scan_network] No mDNS devices; trying dns-sd fallback");
    for service_type in [ANDROID_TV_SERVICE_TYPE].iter() {
            match discover_via_dns_sd(
                service_type,
                &mut devices,
                &mut raw_records,
                &mut seen_device_keys,
                logs,
            ) {
                Ok(_) => {}
                Err(err) => {
                    let msg = format!("dns-sd fallback failed for {}: {}", service_type, err);
                    logs.push(msg.clone());
                    println!("[scan_network] {}", msg);
                }
            }
        }
    }

    if let Err(err) = daemon.shutdown() {
        let msg = format!("mDNS shutdown warning: {}", err);
        logs.push(msg.clone());
        println!("[scan_network] {}", msg);
    }

    (devices, raw_records)
}

fn discover_tvs_via_ssdp(logs: &mut Vec<String>, _local_ip: &str) -> Vec<Device> {
    let mut devices: Vec<Device> = Vec::new();
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => sock,
        Err(err) => {
            let msg = format!("SSDP unavailable: {}", err);
            logs.push(msg.clone());
            println!("[scan_network] {}", msg);
            return Vec::new();
        }
    };

    if let Err(err) = socket.set_read_timeout(Some(Duration::from_secs(1))) {
        let msg = format!("SSDP timeout configuration failed: {}", err);
        logs.push(msg.clone());
        println!("[scan_network] {}", msg);
    }

    let search_targets = [
        "urn:schemas-sony-com:service:ScalarWebAPI:1",
        "urn:schemas-sony-com:service:IRCC:1",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "ssdp:all",
    ];

    for st in search_targets.iter() {
        let request = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {}\r\nUSER-AGENT: sony-tv-remote/0.1\r\n\r\n",
            st
        );

        match socket.send_to(request.as_bytes(), ("239.255.255.250", 1900)) {
            Ok(_) => {
                let msg = format!("SSDP probe sent for {}", st);
                logs.push(msg.clone());
                println!("[scan_network] {}", msg);
            }
            Err(err) => {
                let msg = format!("SSDP send failed for {}: {}", st, err);
                logs.push(msg.clone());
                println!("[scan_network] {}", msg);
            }
        };
    }

    let mut buffer = [0u8; 4096];
    let listen_window = Duration::from_secs(4);
    let start_time = Instant::now();

    while Instant::now().duration_since(start_time) < listen_window {
        match socket.recv_from(&mut buffer) {
            Ok((len, addr)) => {
                let response = String::from_utf8_lossy(&buffer[..len]);
                let response_lower = response.to_lowercase();

                let looks_like_device = response_lower.contains("location:")
                    || response_lower.contains("st:")
                    || response_lower.contains("usn:");

                if looks_like_device {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        let ip_str = ipv4.to_string();
                        let mut name: Option<String> = None;
                        let mut service: Option<String> = None;
                        for line in response.lines() {
                            if line.to_lowercase().starts_with("location:") {
                                // Could fetch name from XML, but for now, use USN or ST
                            } else if line.to_lowercase().starts_with("st:") {
                                service = Some(
                                    line.split(':')
                                        .nth(1)
                                        .unwrap_or("unknown")
                                        .trim()
                                        .to_string(),
                                );
                            } else if line.to_lowercase().starts_with("usn:") {
                                name = Some(
                                    line.split(':')
                                        .last()
                                        .unwrap_or("unknown")
                                        .trim()
                                        .to_string(),
                                );
                            }
                        }
                        devices.push(Device {
                            ip: ip_str.clone(),
                            name,
                            service: service.clone(),
                            status: "Discovered via SSDP".to_string(),
                            mac: None,
                            vendor: None,
                            ports: None,
                        });
                        let msg = format!(
                            "SSDP found device at {} ({})",
                            ip_str,
                            service.as_deref().unwrap_or("unknown")
                        );
                        logs.push(msg.clone());
                        println!("[scan_network] {}", msg);
                    }
                }
            }
            Err(err) => {
                if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                    continue;
                }

                let msg = format!("SSDP receive failed: {}", err);
                logs.push(msg.clone());
                println!("[scan_network] {}", msg);
                break;
            }
        }
    }

    devices
}

#[tauri::command]
fn scan_network(psk: Option<String>, pin: Option<String>) -> Result<ScanResult, String> {
    let mut logs = Vec::new();
    logs.push("Starting network scan for Sony TVs...".to_string());
    println!("[scan_network] Starting network scan");

    let trimmed_psk = psk.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let trimmed_pin = pin.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    let local_ip = local_ip().map_err(|e| {
        let msg = format!("Failed to get local IP: {}", e);
        logs.push(msg.clone());
        println!("[scan_network] {}", msg);
        msg
    })?;

    logs.push(format!("Local IP: {}", local_ip));
    println!("[scan_network] Local IP: {}", local_ip);

    let subnet = match local_ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let subnet_str = format!("{}.{}.{}.", octets[0], octets[1], octets[2]);
            logs.push(format!("Detected subnet: {}x", subnet_str));
            println!("[scan_network] Detected subnet prefix: {}", subnet_str);
            subnet_str
        }
        IpAddr::V6(_) => {
            logs.push("IPv6 not supported for scanning".to_string());
            println!("[scan_network] IPv6 not supported");
            return Err("IPv6 not supported for scanning".to_string());
        }
    };

    logs.push("Discovering Sony TVs via mDNS...".to_string());
    println!("[scan_network] Starting mDNS discovery");

    let (mdns_devices, mdns_raw_records) = discover_tvs_via_mdns(&mut logs);

    logs.push(format!(
        "mDNS discovered {} devices ({} raw records)",
        mdns_devices.len(),
        mdns_raw_records.len()
    ));
    println!(
        "[scan_network] mDNS found {} devices ({} records)",
        mdns_devices.len(),
        mdns_raw_records.len()
    );

    logs.push("Discovering Sony TVs via SSDP/UPnP...".to_string());
    println!("[scan_network] Starting SSDP discovery");

    let ssdp_devices = discover_tvs_via_ssdp(&mut logs, &local_ip.to_string());

    logs.push(format!("SSDP discovered {} devices", ssdp_devices.len()));
    println!("[scan_network] SSDP found {} devices", ssdp_devices.len());

    logs.push("Discovering devices via ARP...".to_string());
    println!("[scan_network] Starting ARP discovery");

    let port_scan_timeout = Duration::from_millis(250);
    let arp_devices = discover_via_arp(&mut logs, &subnet, true, port_scan_timeout);

    logs.push(format!("ARP discovered {} devices", arp_devices.len()));
    println!("[scan_network] ARP found {} devices", arp_devices.len());

    // Collect candidate IPs for Sony probing
    let mut candidate_ips: Vec<String> = Vec::new();
    let mut unique_ips: HashSet<String> = HashSet::new();

    for dev in &mdns_devices {
        if unique_ips.insert(dev.ip.clone()) {
            candidate_ips.push(dev.ip.clone());
        }
    }
    for dev in &ssdp_devices {
        if unique_ips.insert(dev.ip.clone()) {
            candidate_ips.push(dev.ip.clone());
        }
    }
    for dev in &arp_devices {
        if unique_ips.insert(dev.ip.clone()) {
            candidate_ips.push(dev.ip.clone());
        }
    }

    fn discover_via_arp(
        logs: &mut Vec<String>,
        subnet: &str,
        perform_port_scan: bool,
        port_timeout: Duration,
    ) -> Vec<Device> {
        let mut devices: Vec<Device> = Vec::new();

        match Command::new("arp").arg("-a").output() {
            Ok(output) if output.status.success() => {
                let listing = String::from_utf8_lossy(&output.stdout);
                logs.push("Collected ARP table entries".to_string());
                println!("[scan_network] arp -a succeeded");
                let line_regex =
                    Regex::new(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:-]+|\(incomplete\))")
                        .unwrap();

                for line in listing.lines() {
                    if let Some(caps) = line_regex.captures(line) {
                        let ip = caps.get(1).unwrap().as_str().to_string();
                        if !ip.starts_with(subnet) {
                            continue;
                        }

                        let mac_raw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                        let mac = normalize_mac(mac_raw);
                        let vendor = mac
                            .as_deref()
                            .and_then(lookup_vendor)
                            .map(|v| v.to_string());

                        let mut ports: Option<Vec<u16>> = None;
                        if perform_port_scan {
                            if should_scan_ip(&ip) {
                                logs.push(format!(
                                    "Port scan starting for {} over {:?} with {}ms timeout",
                                    ip,
                                    DEFAULT_PORT_SCAN_PORTS,
                                    port_timeout.as_millis()
                                ));
                                println!(
                                    "[scan_network] Port scan start {} ({} ports, {}ms timeout)",
                                    ip,
                                    DEFAULT_PORT_SCAN_PORTS.len(),
                                    port_timeout.as_millis()
                                );
                                let open_ports =
                                    scan_ports(&ip, port_timeout, DEFAULT_PORT_SCAN_PORTS);
                                if open_ports.is_empty() {
                                    logs.push(format!(
                                        "Port scan complete for {}: no open ports detected",
                                        ip
                                    ));
                                } else {
                                    let open_str = open_ports
                                        .iter()
                                        .map(|p| p.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    logs.push(format!(
                                        "Port scan complete for {}: open ports {}",
                                        ip, open_str
                                    ));
                                }
                                println!(
                                    "[scan_network] Port scan complete {} ({} open ports)",
                                    ip,
                                    open_ports.len()
                                );
                                ports = Some(open_ports);
                            } else {
                                logs.push(format!(
                                    "Skipping port scan for {} (broadcast or unsupported address)",
                                    ip
                                ));
                            }
                        }

                        devices.push(Device {
                            ip: ip.clone(),
                            name: None,
                            service: Some("ARP".to_string()),
                            status: "Discovered via ARP".to_string(),
                            mac,
                            vendor,
                            ports,
                        });
                        let msg = format!("ARP found device at {}", ip);
                        logs.push(msg.clone());
                        println!("[scan_network] {}", msg);
                    }
                }
            }
            Ok(output) => {
                logs.push(format!(
                    "arp command returned non-success status: {}",
                    output.status
                ));
                println!(
                    "[scan_network] arp -a non-success status: {}",
                    output.status
                );
            }
            Err(err) => {
                logs.push(format!("Failed to run arp -a: {}", err));
                println!("[scan_network] Failed to run arp -a: {}", err);
            }
        }

        devices
    }

    if candidate_ips.is_empty() {
        logs.push(
            "No devices discovered via ARP; falling back to limited sweep (.100-.120)".to_string(),
        );
        println!("[scan_network] ARP empty; using fallback range");
        for i in 100..121 {
            let fallback_ip = format!("{}{}", subnet, i);
            if unique_ips.insert(fallback_ip.clone()) {
                candidate_ips.push(fallback_ip);
            }
        }
    }

    candidate_ips.sort();

    let mut found_tvs = Vec::new();

    for ip in &candidate_ips {
        logs.push(format!("Testing IP: {}...", ip));
        println!("[scan_network] Testing {}", ip);
        match test_tv_connection(ip.as_str(), &trimmed_psk, &trimmed_pin) {
            TestOutcome::Reachable { transport } => {
                logs.push(format!("Found Sony TV at: {} ({})", ip, transport.label()));
                println!("[scan_network] SUCCESS {} via {}", ip, transport.label());
                found_tvs.push(ip.clone());
            }
            TestOutcome::AuthRequired { status, transport } => {
                logs.push(format!("Warning: Sony TV at {} requires authentication (HTTP {}) via {}. Enter the correct Pre-Shared Key or complete PIN pairing.", ip, status, transport.label()));
                println!(
                    "[scan_network] AUTH REQUIRED {} via {}",
                    ip,
                    transport.label()
                );
                found_tvs.push(ip.clone());
            }
            TestOutcome::NoResponse => {
                logs.push(format!("No response from: {}", ip));
                println!("[scan_network] No response {}", ip);
            }
        }
    }

    logs.push(format!(
        "Scan complete. Found {} Sony TV(s)",
        found_tvs.len()
    ));
    println!(
        "[scan_network] Completed scan. Found {} TVs",
        found_tvs.len()
    );
    if !found_tvs.is_empty() {
        logs.push(format!("Found TVs at: {}", found_tvs.join(", ")));
        println!("[scan_network] Found TVs: {}", found_tvs.join(", "));
    }

    Ok(ScanResult {
        mdns_devices,
        mdns_raw_records,
        ssdp_devices,
        arp_devices,
        sony_tvs: found_tvs,
        logs,
    })
}

fn test_tv_connection(ip: &str, psk: &Option<String>, pin: &Option<String>) -> TestOutcome {
    println!(
        "[test_tv_connection] Testing Sony TV connectivity at {}",
        ip
    );

    let psk_value = psk.as_deref().unwrap_or("").trim().to_string();
    let pin_value = pin.as_deref().unwrap_or("").trim().to_string();

    // Log authentication setup for this connection test
    if !psk_value.is_empty() {
        println!(
            "[test_tv_connection] Using PSK authentication (length: {} chars) for {}",
            psk_value.len(),
            ip
        );
    }
    if !pin_value.is_empty() {
        println!(
            "[test_tv_connection] Using PIN authentication (length: {} chars) for {}",
            pin_value.len(),
            ip
        );
    }
    if psk_value.is_empty() && pin_value.is_empty() {
        println!("[test_tv_connection] No authentication credentials provided for {} - TV may reject probe", ip);
    }

    let client = match build_client(2) {
        Ok(client) => {
            println!(
                "[test_tv_connection] HTTP client built successfully for {}",
                ip
            );
            client
        }
        Err(err) => {
            println!(
                "[test_tv_connection] Failed to build reqwest client for {}: {}",
                ip, err
            );
            return TestOutcome::NoResponse;
        }
    };

    let probe_body = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>AAAAAQAAAAEAAAAvAw==</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#;
    println!(
        "[test_tv_connection] Using IRCC probe command (Power) to test {} connectivity",
        ip
    );

    let mut last_error: Option<String> = None;
    let transports = [
        Transport::Http,
        Transport::Https,
        Transport::Http6466,
        Transport::Https6466,
    ];

    println!(
        "[test_tv_connection] Testing {} via {} transport methods",
        ip,
        transports.len()
    );

    for transport in transports {
        println!(
            "[test_tv_connection] Probing {} via {} ({})",
            ip,
            transport.label(),
            transport.url(ip)
        );

        match perform_ircc_request(&client, ip, probe_body, &psk_value, &pin_value, transport) {
            Ok(status) => {
                println!(
                    "[test_tv_connection] {} via {} returned: HTTP {}",
                    ip,
                    transport.label(),
                    status
                );

                if status.is_success() {
                    println!(
                        "[test_tv_connection] SUCCESS: {} is reachable via {} - Sony TV confirmed",
                        ip,
                        transport.label()
                    );
                    return TestOutcome::Reachable { transport };
                }
                if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    println!("[test_tv_connection] AUTH REQUIRED: {} requires authentication via {} (HTTP {})", ip, transport.label(), status);
                    println!("[test_tv_connection] TV is present but needs PSK or PIN pairing");
                    return TestOutcome::AuthRequired { status, transport };
                }
                if matches!(transport, Transport::Http | Transport::Http6466) {
                    let retry_transport = if transport == Transport::Http {
                        Transport::Https
                    } else {
                        Transport::Https6466
                    };
                    println!(
                        "[test_tv_connection] {} responded with HTTP {} over {}; retrying with secure transport {}",
                        ip, status, transport.label(), retry_transport.label()
                    );
                    last_error = Some(format!("HTTP {}", status));
                    continue;
                }
                println!(
                    "[test_tv_connection] {} responded with HTTP {} over HTTPS",
                    ip, status
                );
                last_error = Some(format!("HTTP {}", status));
            }
            Err(err) => {
                println!(
                    "[test_tv_connection] CONNECTION ERROR: {} via {} failed: {}",
                    ip,
                    transport.label(),
                    err
                );
                last_error = Some(err.to_string());
            }
        }
    }

    if last_error.is_some() {
        println!(
            "[test_tv_connection] No successful connection to {} - all transports failed",
            ip
        );
    } else {
        println!(
            "[test_tv_connection] No response from {} - device may not be a Sony TV or unreachable",
            ip
        );
    }

    TestOutcome::NoResponse
}

fn build_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .build()
}

fn perform_ircc_request(
    client: &Client,
    ip: &str,
    body: &str,
    psk: &str,
    pin: &str,
    transport: Transport,
) -> Result<StatusCode, reqwest::Error> {
    println!(
        "[perform_ircc_request] Preparing IRCC request to {} via {}",
        ip,
        transport.label()
    );
    println!("[perform_ircc_request] Target URL: {}", transport.url(ip));

    let mut request = client
        .post(transport.url(ip))
        .header("Content-Type", "text/xml; charset=UTF-8")
        .header(
            "SOAPACTION",
            r#""urn:schemas-sony-com:service:IRCC:1#X_SendIRCC""#,
        )
        .body(body.to_string());

    // Detailed authentication header logging
    if !psk.is_empty() {
        request = request.header("X-Auth-PSK", psk);
        println!(
            "[perform_ircc_request] Adding X-Auth-PSK header (length: {} chars)",
            psk.len()
        );
    } else {
        println!("[perform_ircc_request] No X-Auth-PSK header (PSK not provided)");
    }

    if !pin.is_empty() {
        request = request.header("X-Auth-PIN", pin);
        println!(
            "[perform_ircc_request] Adding X-Auth-PIN header (length: {} chars)",
            pin.len()
        );
    } else {
        println!("[perform_ircc_request] No X-Auth-PIN header (PIN not provided)");
    }

    println!(
        "[perform_ircc_request] Sending SOAP request with body length: {} chars",
        body.len()
    );
    println!("[perform_ircc_request] SOAP Action: urn:schemas-sony-com:service:IRCC:1#X_SendIRCC");

    let response = request.send()?;
    let status = response.status();

    println!(
        "[perform_ircc_request] Received response with status: {} ({})",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown")
    );

    if status.is_success() {
        println!("[perform_ircc_request] HTTP success - validating Sony TV response...");

        // Check if this is actually a Sony TV by examining the response body
        if let Ok(text) = response.text() {
            println!(
                "[perform_ircc_request] Response body length: {} chars",
                text.len()
            );

            if text.contains("Sony") || text.contains("urn:schemas-sony-com") {
                println!("[perform_ircc_request] SUCCESS: Confirmed Sony TV response (contains Sony identifiers)");
                return Ok(status);
            } else {
                println!(
                    "[perform_ircc_request] WARNING: {} responded with success but response doesn't contain Sony-specific content",
                    ip
                );
                println!(
                    "[perform_ircc_request] Response preview: {}",
                    &text[..std::cmp::min(200, text.len())]
                );
                return Ok(StatusCode::NOT_FOUND); // Treat as not found
            }
        } else {
            println!("[perform_ircc_request] Could not read response body for validation");
        }
    } else {
        println!("[perform_ircc_request] HTTP error response - authentication or command may have failed");
    }

    Ok(status)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            send_ircc,
            scan_network,
            cast_launch_app,
            test_connection,
            start_pairing,
            complete_pairing,
            send_remote_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
