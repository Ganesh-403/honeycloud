use reqwest::Client;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::collections::HashMap;
use crate::config::Config;

pub async fn resolve_ip(ip: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    
    if ip == "127.0.0.1" || ip == "0.0.0.0" || ip.starts_with("192.168.") || ip.starts_with("10.") {
        map.insert("country".to_string(), "Local Network".to_string());
        map.insert("country_code".to_string(), "LO".to_string());
        map.insert("city".to_string(), "Internal".to_string());
        map.insert("isp".to_string(), "Localhost".to_string());
        return map;
    }

    let client = Client::new();
    let url = format!("http://ip-api.com/json/{}", ip);

    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<HashMap<String, serde_json::Value>>().await {
            if json.get("status").and_then(|v| v.as_str()) == Some("success") {
                map.insert("country".to_string(), json.get("country").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string());
                map.insert("country_code".to_string(), json.get("countryCode").and_then(|v| v.as_str()).unwrap_or("XX").to_string());
                map.insert("city".to_string(), json.get("city").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string());
                map.insert("isp".to_string(), json.get("isp").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string());
                return map;
            }
        }
    }

    map.insert("country".to_string(), "Unknown".to_string());
    map.insert("country_code".to_string(), "XX".to_string());
    map.insert("city".to_string(), "Unknown".to_string());
    map.insert("isp".to_string(), "Unknown".to_string());
    map
}

pub async fn send_telegram_message(config: &Config, message: &str) {
    if !config.telegram_alerts_enabled || config.telegram_bot_token.is_empty() || config.telegram_chat_id.is_empty() {
        return;
    }

    let client = Client::new();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", config.telegram_bot_token);
    
    let mut params = HashMap::new();
    params.insert("chat_id", &config.telegram_chat_id);
    params.insert("text", &message);
    params.insert("parse_mode", &"Markdown");

    let _ = client.post(&url).json(&params).send().await;
}

pub async fn send_email_alert(config: &Config, subject: &str, body: &str) {
    if !config.email_alerts_enabled || config.email_to.is_empty() {
        return;
    }

    let from_email = if config.email_from.is_empty() { "no-reply@honeycloud.com" } else { &config.email_from };

    let email = Message::builder()
        .from(from_email.parse().unwrap())
        .to(config.email_to.parse().unwrap())
        .subject(subject)
        .body(body.to_string())
        .unwrap();

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

    let mailer = SmtpTransport::relay(&config.smtp_host)
        .unwrap()
        .port(config.smtp_port)
        .credentials(creds)
        .build();

    tokio::task::spawn_blocking(move || {
        let _ = mailer.send(&email);
    });
}
