#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use flume::RecvTimeoutError as FlumeRecvTimeoutError;
use local_ip_address::local_ip;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};
use std::thread;
use tauri::command;

#[command]
fn test_connection(ip: String) -> Result<String, String> {
    println!("[test_connection] Testing connection to {}", ip);
    
    let output = Command::new("/sbin/ping")
        .arg("-c")
        .arg("4")
        .arg(&ip)
        .output()
        .map_err(|e| {
            println!("[test_connection] Failed to run ping command: {}", e);
            format!("Failed to run ping: {}", e)
        })?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status;
    
    println!("[test_connection] Ping status: {}", status);
    println!("[test_connection] Ping stdout: {}", stdout);
    println!("[test_connection] Ping stderr: {}", stderr);
    
    if status.success() {
        println!("[test_connection] Ping successful");
        Ok(format!("Connection successful:\n{}", stdout))
    } else {
        println!("[test_connection] Ping failed");
        Err(format!("Connection failed:\nStatus: {}\nStdout: {}\nStderr: {}", status, stdout, stderr))
    }
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

    for transport in [Transport::Http, Transport::Https, Transport::Http6466, Transport::Https6466] {
        match perform_ircc_request(&client, &ip, &body, &trimmed_psk, &trimmed_pin, transport) {
            Ok(status) => {
                if status.is_success() {
                    let via = transport.label();
                    return Ok(format!("Command sent successfully via {}", via));
                } else if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    let via = transport.label();
                    return Err(format!("TV rejected the command (HTTP {}) via {}. Ensure the Pre-Shared Key matches the one configured on the TV or complete PIN pairing.", status.as_u16(), via));
                } else if matches!(transport, Transport::Http | Transport::Http6466) {
                    let retry_transport = if transport == Transport::Http { Transport::Https } else { Transport::Https6466 };
                    println!(
                        "[send_ircc] {} responded with HTTP {} over {}; retrying with {}",
                        ip, status, transport.label(), retry_transport.label()
                    );
                    last_error = Some(format!("HTTP {}", status));
                    continue;
                } else {
                    return Err(format!("Failed to send command via {}: HTTP {}", transport.label(), status));
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

#[command]
fn cast_launch_app(ip: String, app_name: String, psk: Option<String>) -> Result<String, String> {
    println!("[cast_launch_app] Starting app launch for '{}' on TV at {}", app_name, ip);
    
    let client = build_client(10).map_err(|e| {
        println!("[cast_launch_app] Failed to build HTTP client: {}", e);
        format!("Failed to build HTTP client: {}", e)
    })?;
    
    let app_id = app_name.clone();
    let url = format!("http://{}:8008/apps/{}", ip, app_id);
    println!("[cast_launch_app] Using URL: {}", url);
    
    let mut request = client.post(&url);
    
    if let Some(ref psk_val) = psk {
        if !psk_val.trim().is_empty() {
            request = request.header("X-Auth-PSK", psk_val.trim());
            println!("[cast_launch_app] Added X-Auth-PSK header");
        } else {
            println!("[cast_launch_app] PSK provided but empty, skipping header");
        }
    } else {
        println!("[cast_launch_app] No PSK provided");
    }
    
    println!("[cast_launch_app] Sending POST request...");
    let response = request.send().map_err(|e| {
        println!("[cast_launch_app] Request failed: {}", e);
        format!("Failed to send request to {}: {}", url, e)
    })?;
    
    let status = response.status();
    println!("[cast_launch_app] Response status: {}", status);
    
    if status.is_success() {
        println!("[cast_launch_app] Launch successful");
        Ok(format!("Successfully launched {} on TV at {}", app_name, ip))
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

    let output = child.wait_with_output().map_err(|e| format!("Failed to get dns-sd output: {}", e))?;

    if !output.status.success() && !output.status.code().map_or(true, |c| c == 9 || c == 143) { // Allow if killed by signal or SIGKILL/SIGTERM
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

        let output = child.wait_with_output().map_err(|e| format!("Failed to get dns-sd -L output for {}: {}", instance, e))?;

        if !output.status.success() && !output.status.code().map_or(true, |c| c == 9 || c == 143) {
            logs.push(format!("dns-sd -L failed for {}: {}", instance, output.status));
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
                    logs.push(format!("Failed to resolve hostname {} for {}", host, instance));
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
        "_androidtvremote2._tcp.local.",
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
        for service_type in ["_androidtvremote2._tcp"].iter() {
            match discover_via_dns_sd(service_type, &mut devices, &mut raw_records, &mut seen_device_keys, logs) {
                Ok(_) => {},
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

fn discover_tvs_via_ssdp(logs: &mut Vec<String>, local_ip: &str) -> Vec<Device> {
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

    for transport in [Transport::Http, Transport::Https, Transport::Http6466, Transport::Https6466] {
        match perform_ircc_request(&client, ip, probe_body, &psk_value, &pin_value, transport) {
            Ok(status) => {
                if status.is_success() {
                    return TestOutcome::Reachable { transport };
                }
                if matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) {
                    return TestOutcome::AuthRequired { status, transport };
                }
                if matches!(transport, Transport::Http | Transport::Http6466) {
                    let retry_transport = if transport == Transport::Http { Transport::Https } else { Transport::Https6466 };
                    println!(
                        "[scan_network] {} responded with HTTP {} over {}; retrying with {}",
                        ip, status, transport.label(), retry_transport.label()
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![send_ircc, scan_network, cast_launch_app, test_connection])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
