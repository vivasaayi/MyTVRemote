#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use local_ip_address::local_ip;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;
use tauri::command;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![send_ircc, scan_network])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[command]
fn send_ircc(
    ip: String,
    code: String,
    psk: Option<String>,
    pin: Option<String>,
) -> Result<String, String> {
    let body = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>{}</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#,
        code
    );
    let client = build_client(5).map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let trimmed_psk = psk.unwrap_or_default().trim().to_string();
    let trimmed_pin = pin.unwrap_or_default().trim().to_string();

    let mut last_error: Option<String> = None;

    for transport in [Transport::Http, Transport::Https] {
        match perform_ircc_request(&client, &ip, &body, &trimmed_psk, &trimmed_pin, transport) {
            Ok(status) => {
                if status.is_success() {
                    let via = transport.label();
                    return Ok(format!("Command sent successfully via {}", via));
                } else if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    let via = transport.label();
                    return Err(format!("TV rejected the command (HTTP {}) via {}. Ensure the Pre-Shared Key matches the one configured on the TV or complete PIN pairing.", status.as_u16(), via));
                } else if transport == Transport::Http {
                    println!(
                        "[send_ircc] {} responded with HTTP {} over HTTP; retrying with HTTPS",
                        ip, status
                    );
                    last_error = Some(format!("HTTP {}", status));
                    continue;
                } else {
                    return Err(format!("Failed to send command via HTTPS: HTTP {}", status));
                }
            }
            Err(err) => {
                println!(
                    "[send_ircc] {} request over {} failed: {}",
                    ip,
                    transport.label(),
                    err
                );
                last_error = Some(err.to_string());
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "Unable to reach TV over HTTP or HTTPS.".to_string()))
}

#[derive(Serialize, Deserialize)]
struct ScanResult {
    ips: Vec<String>,
    logs: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Http,
    Https,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Transport::Http => "HTTP",
            Transport::Https => "HTTPS",
        }
    }

    fn url(self, ip: &str) -> String {
        match self {
            Transport::Http => format!("http://{}/sony/IRCC", ip),
            Transport::Https => format!("https://{}/sony/IRCC", ip),
        }
    }
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

#[command]
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

    let mdns_ips = Vec::new();
    // TODO: Implement mDNS discovery
    // if let Ok(discovery) = mdns::discover::all("_sonytv._tcp.local.", Duration::from_secs(3)) {
    //     for result in discovery {
    //         if let Ok(response) = result {
    //             if let Some(addr) = response.ip_addr() {
    //                 let ip_str = addr.to_string();
    //                 logs.push(format!("mDNS found potential TV: {}", ip_str));
    //                 println!("[scan_network] mDNS: {}", ip_str);
    //                 mdns_ips.push(ip_str);
    //             }
    //         }
    //     }
    // } else {
    //     logs.push("mDNS discovery failed".to_string());
    // }

    logs.push(format!("mDNS discovered {} potential TVs", mdns_ips.len()));
    println!("[scan_network] mDNS found {} TVs", mdns_ips.len());

    let mut candidate_ips: Vec<String> = mdns_ips;
    let mut unique_ips: HashSet<String> = HashSet::new();

    match Command::new("arp").arg("-a").output() {
        Ok(output) if output.status.success() => {
            let listing = String::from_utf8_lossy(&output.stdout);
            logs.push("Collected ARP table entries".to_string());
            println!("[scan_network] arp -a succeeded");
            let ip_regex = Regex::new(r"(\d+\.\d+\.\d+\.\d+)").unwrap();
            for cap in ip_regex.captures_iter(&listing) {
                if let Some(ip_match) = cap.get(0) {
                    let ip = ip_match.as_str().to_string();
                    if ip.starts_with(&subnet) && unique_ips.insert(ip.clone()) {
                        candidate_ips.push(ip);
                    }
                }
            }
            logs.push(format!(
                "ARP table contains {} device(s) in subnet",
                candidate_ips.len()
            ));
            println!(
                "[scan_network] ARP subnet device count: {}",
                candidate_ips.len()
            );
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

    if candidate_ips.is_empty() {
        logs.push(
            "No devices discovered via ARP; falling back to limited sweep (.100-.120)".to_string(),
        );
        println!("[scan_network] ARP empty; using fallback range");
        for i in 100..121 {
            candidate_ips.push(format!("{}{}", subnet, i));
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
        ips: found_tvs,
        logs,
    })
}

fn test_tv_connection(ip: &str, psk: &Option<String>, pin: &Option<String>) -> TestOutcome {
    let client = match build_client(2) {
        Ok(client) => client,
        Err(err) => {
            println!("[scan_network] Failed to build reqwest client: {}", err);
            return TestOutcome::NoResponse;
        }
    };

    let probe_body = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>AAAAAQAAAAEAAAAvAw==</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#;
    let psk_value = psk.as_deref().unwrap_or("").trim().to_string();
    let pin_value = pin.as_deref().unwrap_or("").trim().to_string();
    let mut last_error: Option<String> = None;

    for transport in [Transport::Http, Transport::Https] {
        match perform_ircc_request(&client, ip, probe_body, &psk_value, &pin_value, transport) {
            Ok(status) => {
                if status.is_success() {
                    return TestOutcome::Reachable { transport };
                }
                if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    return TestOutcome::AuthRequired { status, transport };
                }
                if transport == Transport::Http {
                    println!(
                        "[scan_network] {} responded with HTTP {} over HTTP; retrying with HTTPS",
                        ip, status
                    );
                    last_error = Some(format!("HTTP {}", status));
                    continue;
                }
                println!(
                    "[scan_network] {} responded with HTTP {} over HTTPS",
                    ip, status
                );
                return TestOutcome::NoResponse;
            }
            Err(err) => {
                println!(
                    "[scan_network] {} request over {} failed: {}",
                    ip,
                    transport.label(),
                    err
                );
                last_error = Some(err.to_string());
                continue;
            }
        }
    }

    if let Some(err) = last_error {
        println!("[scan_network] HTTP error while probing {}: {}", ip, err);
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
    let mut request = client
        .post(transport.url(ip))
        .header("Content-Type", "text/xml; charset=UTF-8")
        .header(
            "SOAPACTION",
            r#""urn:schemas-sony-com:service:IRCC:1#X_SendIRCC""#,
        )
        .body(body.to_string());

    if !psk.is_empty() {
        request = request.header("X-Auth-PSK", psk);
    }
    if !pin.is_empty() {
        request = request.header("X-Auth-PIN", pin);
    }

    let response = request.send()?;
    let status = response.status();

    if status.is_success() {
        // Check if this is actually a Sony TV by examining the response body
        if let Ok(text) = response.text() {
            if text.contains("Sony") || text.contains("urn:schemas-sony-com") {
                return Ok(status);
            } else {
                println!(
                    "[perform_ircc_request] {} responded with success but not Sony-specific content",
                    ip
                );
                return Ok(StatusCode::NOT_FOUND); // Treat as not found
            }
        }
    }

    Ok(status)
}
