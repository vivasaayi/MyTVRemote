#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use tauri::command;
use std::net::IpAddr;
use std::collections::HashSet;
use std::process::Command;
use local_ip_address::local_ip;
use regex::Regex;

fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![send_ircc, scan_network])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

#[command]
fn send_ircc(ip: String, code: String) -> Result<String, String> {
  let url = format!("http://{}:80/sony/IRCC", ip);
  let body = format!(r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>{}</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#, code);
  let client = reqwest::blocking::Client::new();
  let res = client
    .post(&url)
    .header("Content-Type", "text/xml; charset=UTF-8")
    .header("SOAPACTION", r#""urn:schemas-sony-com:service:IRCC:1#X_SendIRCC""#)
    .body(body)
    .send()
    .map_err(|e| e.to_string())?;
  if res.status().is_success() {
    Ok("Command sent successfully".to_string())
  } else {
    Err(format!("Failed to send command: HTTP {}", res.status()))
  }
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ScanResult {
    ips: Vec<String>,
    logs: Vec<String>,
}

#[command]
fn scan_network() -> Result<ScanResult, String> {
  let mut logs = Vec::new();
  logs.push("Starting network scan for Sony TVs...".to_string());
  println!("[scan_network] Starting network scan");
  
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

  let mut candidate_ips: Vec<String> = Vec::new();
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
      logs.push(format!("ARP table contains {} device(s) in subnet", candidate_ips.len()));
      println!("[scan_network] ARP subnet device count: {}", candidate_ips.len());
    }
    Ok(output) => {
      logs.push(format!("arp command returned non-success status: {}", output.status));
      println!("[scan_network] arp -a non-success status: {}", output.status);
    }
    Err(err) => {
      logs.push(format!("Failed to run arp -a: {}", err));
      println!("[scan_network] Failed to run arp -a: {}", err);
    }
  }

  if candidate_ips.is_empty() {
    logs.push("No devices discovered via ARP; falling back to limited sweep (.100-.120)".to_string());
    println!("[scan_network] ARP empty; using fallback range");
    for i in 100..121 {
      candidate_ips.push(format!("{}{}", subnet, i));
    }
  }

  candidate_ips.sort();

  let mut found_tvs = Vec::new();
  
  for ip in candidate_ips {
    logs.push(format!("Testing IP: {}...", ip));
    println!("[scan_network] Testing {}", ip);
    match test_tv_connection(&ip) {
      true => {
        logs.push(format!("✓ Found Sony TV at: {}", ip));
        println!("[scan_network] SUCCESS {}", ip);
        found_tvs.push(ip);
      }
      false => {
        logs.push(format!("✗ No response from: {}", ip));
        println!("[scan_network] No response {}", ip);
      }
    }
  }
  
  logs.push(format!("Scan complete. Found {} Sony TV(s)", found_tvs.len()));
  println!("[scan_network] Completed scan. Found {} TVs", found_tvs.len());
  if !found_tvs.is_empty() {
    logs.push(format!("Found TVs at: {}", found_tvs.join(", ")));
    println!("[scan_network] Found TVs: {}", found_tvs.join(", "));
  }
  
  Ok(ScanResult { ips: found_tvs, logs })
}

fn test_tv_connection(ip: &str) -> bool {
  let url = format!("http://{}:80/sony/IRCC", ip);
  let body = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:X_SendIRCC xmlns:u="urn:schemas-sony-com:service:IRCC:1"><IRCCCode>AAAAAQAAAAEAAAAvAw==</IRCCCode></u:X_SendIRCC></s:Body></s:Envelope>"#;
  
  let client = reqwest::blocking::Client::builder()
    .timeout(std::time::Duration::from_secs(2))
    .build()
    .unwrap();
    
  match client
    .post(&url)
    .header("Content-Type", "text/xml; charset=UTF-8")
    .header("SOAPACTION", r#""urn:schemas-sony-com:service:IRCC:1#X_SendIRCC""#)
    .body(body)
    .send()
  {
    Ok(response) => response.status().is_success(),
    Err(_) => false,
  }
}