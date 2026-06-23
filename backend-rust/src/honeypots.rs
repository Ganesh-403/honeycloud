use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use sqlx::PgPool;
use std::sync::Arc;
use chrono::Utc;
use serde_json::json;
use crate::config::Config;
use crate::websocket::WebSocketState;
use crate::ml::{extract_features, predict_lstm};
use crate::mitre::map_event;
use crate::services::{resolve_ip, send_telegram_message, send_email_alert};

pub fn start_honeypots(pool: PgPool, config: Config, ws_state: Arc<WebSocketState>) {
    let ws_clone = ws_state.clone();
    
    // SSH
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("SSH", c.ssh_honeypot_port, p, c, ws, handle_ssh).await;
    });

    // FTP
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("FTP", c.ftp_honeypot_port, p, c, ws, handle_ftp).await;
    });

    // HTTP
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("HTTP", c.http_honeypot_port, p, c, ws, handle_http).await;
    });

    // TELNET
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("TELNET", c.telnet_honeypot_port, p, c, ws, handle_telnet).await;
    });

    // SMTP
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("SMTP", c.smtp_honeypot_port, p, c, ws, handle_smtp).await;
    });

    // RDP
    let p = pool.clone(); let c = config.clone(); let ws = ws_clone.clone();
    tokio::spawn(async move {
        start_tcp_honeypot("RDP", c.rdp_honeypot_port, p, c, ws, handle_rdp).await;
    });
}

// ── Generic TCP Listener ─────────────────────────────────────────────────────
async fn start_tcp_honeypot<F, Fut>(
    name: &'static str,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
    handler: F,
) where
    F: Fn(tokio::net::TcpStream, String, u16, PgPool, Config, Arc<WebSocketState>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await;
    if let Err(e) = listener {
        eprintln!("Failed to bind {} Honeypot to {}: {}", name, addr, e);
        return;
    }
    let listener = listener.unwrap();
    println!("{} Honeypot listening on port {}", name, port);

    while let Ok((socket, peer_addr)) = listener.accept().await {
        let ip = peer_addr.ip().to_string();
        let client_port = peer_addr.port();
        let p = pool.clone();
        let c = config.clone();
        let ws = ws_state.clone();
        
        let fut = handler(socket, ip, client_port, p, c, ws);
        tokio::spawn(fut);
    }
}

// ── SSH Handshake Emulator ───────────────────────────────────────────────
async fn handle_ssh(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut reader = BufReader::new(&mut stream);
    
    // Write SSH banner
    let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n").await;
    
    let mut client_banner = String::new();
    if reader.read_line(&mut client_banner).await.is_ok() {
        // Read key exchange payload and prompt for password
        let mut user = "root".to_string();
        let mut pass = "admin".to_string();
        
        ingest_event(&pool, &config, &ws_state, "SSH", &ip, port, &user, &pass, "SSH Authentication attempt").await;
    }
}

// ── FTP Connection Handler ───────────────────────────────────────────────
async fn handle_ftp(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut stream = stream;
    let _ = stream.write_all(b"220 FTP server ready\r\n").await;
    
    let mut reader = BufReader::new(&mut stream);
    let mut user = String::new();
    let mut pass = String::new();

    while let Ok(n) = reader.read_line(&mut user).await {
        if n == 0 { break; }
        if user.to_uppercase().starts_with("USER") {
            let _ = stream.write_all(b"331 Password required\r\n").await;
            if reader.read_line(&mut pass).await.is_ok() {
                let _ = stream.write_all(b"230 User logged in, proceed\r\n").await;
                
                let u = user.trim_start_matches("USER").trim().to_string();
                let p = pass.trim_start_matches("PASS").trim().to_string();
                ingest_event(&pool, &config, &ws_state, "FTP", &ip, port, &u, &p, "FTP Login attempt").await;
            }
            break;
        }
    }
}

// ── HTTP Connection Handler ──────────────────────────────────────────────
async fn handle_http(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_ok() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let path = if parts.len() > 1 { parts[1] } else { "/" };
        
        ingest_event(&pool, &config, &ws_state, "HTTP", &ip, port, "", "", &format!("GET {}", path)).await;
        
        let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Honey Cloud</h1></body></html>";
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

// ── Telnet Connection Handler ────────────────────────────────────────────
async fn handle_telnet(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut stream = stream;
    let _ = stream.write_all(b"login: ").await;
    let mut reader = BufReader::new(&mut stream);
    let mut user = String::new();
    let mut pass = String::new();
    
    if reader.read_line(&mut user).await.is_ok() {
        let _ = stream.write_all(b"Password: ").await;
        if reader.read_line(&mut pass).await.is_ok() {
            let _ = stream.write_all(b"Login incorrect\r\n").await;
            ingest_event(&pool, &config, &ws_state, "TELNET", &ip, port, user.trim(), pass.trim(), "Telnet Login attempt").await;
        }
    }
}

// ── SMTP Connection Handler ──────────────────────────────────────────────
async fn handle_smtp(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut stream = stream;
    let _ = stream.write_all(b"220 smtp.honeycloud.com ESMTP ready\r\n").await;
    
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line).await {
        if n == 0 { break; }
        if line.to_uppercase().starts_with("HELO") || line.to_uppercase().starts_with("EHLO") {
            let _ = stream.write_all(format!("250 Hello {}\r\n", ip).as_bytes()).await;
        } else if line.to_uppercase().starts_with("MAIL FROM") {
            let _ = stream.write_all(b"250 2.1.0 Sender OK\r\n").await;
        } else if line.to_uppercase().starts_with("RCPT TO") {
            let _ = stream.write_all(b"250 2.1.5 Recipient OK\r\n").await;
        } else if line.to_uppercase().starts_with("DATA") {
            let _ = stream.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").await;
            let mut email = String::new();
            while let Ok(m) = reader.read_line(&mut email).await {
                if m == 0 || email.trim() == "." {
                    let _ = stream.write_all(b"250 2.0.0 OK : Message received\r\n").await;
                    break;
                }
            }
            ingest_event(&pool, &config, &ws_state, "SMTP", &ip, port, "", "", "Mail transfer attempts").await;
            break;
        } else if line.to_uppercase().starts_with("QUIT") {
            let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
            break;
        } else {
            let _ = stream.write_all(b"500 Syntax error\r\n").await;
        }
        line.clear();
    }
}

// ── RDP Connection Handler ───────────────────────────────────────────────
async fn handle_rdp(
    mut stream: tokio::net::TcpStream,
    ip: String,
    port: u16,
    pool: PgPool,
    config: Config,
    ws_state: Arc<WebSocketState>,
) {
    let mut buffer = [0; 1024];
    if let Ok(n) = stream.try_read(&mut buffer) {
        if n > 0 {
            ingest_event(&pool, &config, &ws_state, "RDP", &ip, port, "", "", &format!("RDP Payload size: {} bytes", n)).await;
        }
    }
}

// ── Ingest pipeline logic ────────────────────────────────────────────────
async fn ingest_event(
    pool: &PgPool,
    config: &Config,
    ws_state: &Arc<WebSocketState>,
    service: &str,
    ip: &str,
    port: u16,
    user: &str,
    pass: &str,
    command: &str,
) {
    let now = Utc::now();
    let features = extract_features(service, user, pass, command, Some(port as i32), now);
    let pred = predict_lstm(&features);

    let default_severity = if !command.is_empty() {
        if command.contains("rm -rf") || command.contains("wget") || command.contains("curl") {
            "CRITICAL"
        } else {
            "HIGH"
        }
    } else if !pass.is_empty() {
        "MEDIUM"
    } else {
        "LOW"
    };

    // Save event
    let event_id: (i64,) = sqlx::query_as(
        "INSERT INTO attack_events (service, source_ip, source_port, timestamp, username, password, command, severity, score, label)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id"
    )
    .bind(service)
    .bind(ip)
    .bind(port as i32)
    .bind(now)
    .bind(user)
    .bind(pass)
    .bind(command)
    .bind(default_severity)
    .bind(pred.score)
    .bind(&pred.label)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if event_id.0 == 0 {
        return;
    }

    // MITRE ATT&CK Mapping
    let mitre_matches = map_event(service, user, pass, command, "", "");
    for m in mitre_matches {
        let _ = sqlx::query(
            "INSERT INTO mitre_mappings (event_id, technique_id, technique_name, tactic, confidence, mapped_at)
             VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(event_id.0)
        .bind(m.technique_id)
        .bind(m.technique_name)
        .bind(m.tactic)
        .bind(m.confidence)
        .bind(Utc::now())
        .execute(pool)
        .await;
    }

    // Trigger asynchronous profiler updates
    let p_pool = pool.clone();
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        profile_attacker(p_pool, ip_str).await;
    });

    // Resolve location
    let geo = resolve_ip(ip).await;
    let country = geo.get("country").cloned().unwrap_or_else(|| "Unknown".to_string());
    let city = geo.get("city").cloned().unwrap_or_else(|| "Unknown".to_string());

    // Broadcast event JSON on WebSocket channel
    let ws_msg = json!({
        "type": "new_attack",
        "data": {
            "id": event_id.0,
            "timestamp": now.to_rfc3339(),
            "service": service,
            "source_ip": ip,
            "source_port": port,
            "username": user,
            "password": pass,
            "command": command,
            "severity": default_severity,
            "score": pred.score,
            "label": pred.label,
            "country": country
        }
    }).to_string();
    let _ = ws_state.tx.send(ws_msg);

    // Send notifications if severity triggers high thresholds
    if default_severity == "HIGH" || default_severity == "CRITICAL" {
        let alert_text = format!(
            "*HIGH SEVERITY ATTACK DETECTED*\nService: {}\nAttacker IP: {}\nLocation: {}, {}\nSeverity: {}\nCredentials: {}:{}\nCommand: {}",
            service, ip, city, country, default_severity, user, pass, command
        );
        let c = config.clone();
        tokio::spawn(async move {
            send_telegram_message(&c, &alert_text).await;
            send_email_alert(&c, &format!("HoneyCloud Attack Alert: {}", default_severity), &alert_text).await;
        });
    }
}

// ── Profile updating logic ───────────────────────────────────────────────
async fn profile_attacker(pool: PgPool, ip: String) {
    let now = Utc::now();
    let five_min_ago = now - chrono::Duration::minutes(5);
    let one_min_ago = now - chrono::Duration::seconds(60);

    // Fetch totals
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM attack_events WHERE source_ip = $1")
        .bind(&ip)
        .fetch_one(&pool)
        .await
        .unwrap_or((0,));

    if total.0 == 0 { return; }

    // Fetch counts for threshold rules
    let last_1min: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM attack_events WHERE source_ip = $1 AND timestamp >= $2"
    )
    .bind(&ip)
    .bind(one_min_ago)
    .fetch_one(&pool)
    .await
    .unwrap_or((0,));

    let unique_services: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT service) FROM attack_events WHERE source_ip = $1 AND timestamp >= $2"
    )
    .bind(&ip)
    .bind(five_min_ago)
    .fetch_one(&pool)
    .await
    .unwrap_or((0,));

    let unique_passwords: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT password) FROM attack_events WHERE source_ip = $1 AND password != '' AND timestamp >= $2"
    )
    .bind(&ip)
    .bind(five_min_ago)
    .fetch_one(&pool)
    .await
    .unwrap_or((0,));

    let critical_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM attack_events WHERE source_ip = $1 AND severity = 'CRITICAL'"
    )
    .bind(&ip)
    .fetch_one(&pool)
    .await
    .unwrap_or((0,));

    let high_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM attack_events WHERE source_ip = $1 AND severity = 'HIGH'"
    )
    .bind(&ip)
    .fetch_one(&pool)
    .await
    .unwrap_or((0,));

    let brute_force = last_1min.0 >= 10;
    let credential_stuffing = unique_passwords.0 >= 5;
    let port_scanner = unique_services.0 >= 3;

    let mut score = (critical_events.0 * 4 + high_events.0 * 2) as i32;
    if brute_force { score += 15; }
    if credential_stuffing { score += 10; }
    if port_scanner { score += 8; }

    let tier = if score >= 50 {
        "CRITICAL"
    } else if score >= 20 {
        "HIGH"
    } else if score >= 8 {
        "MEDIUM"
    } else if score >= 2 {
        "LOW"
    } else {
        "UNKNOWN"
    };

    // Update profile
    let _ = sqlx::query(
        "INSERT INTO attacker_profiles (ip_address, risk_score, risk_tier, is_blocked, created_at, updated_at, total_events)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (ip_address) DO UPDATE 
         SET risk_score = EXCLUDED.risk_score, risk_tier = CASE WHEN attacker_profiles.is_blocked THEN 'BLOCKED' ELSE EXCLUDED.risk_tier END, 
             updated_at = EXCLUDED.updated_at, total_events = EXCLUDED.total_events"
    )
    .bind(&ip)
    .bind(score)
    .bind(tier)
    .bind(false)
    .bind(now)
    .bind(now)
    .bind(total.0 as i32)
    .execute(&pool)
    .await;
}
