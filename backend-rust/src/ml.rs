use chrono::{DateTime, Utc, Timelike};
use regex::Regex;
use lazy_static::lazy_static;
use std::collections::HashMap;
use serde::Serialize;

pub const FEATURE_NAMES: [&str; 10] = [
    "service_port", "username_len", "password_len", "command_len", "source_port",
    "hour_of_day", "dangerous_pattern_count", "is_root_user", "is_anonymous_user", "has_command"
];

lazy_static! {
    static ref DANGEROUS_RE: Vec<Regex> = vec![
        Regex::new(r"(?i)rm\s+-rf").unwrap(),
        Regex::new(r"(?i)cat\s+/etc").unwrap(),
        Regex::new(r"(?i)wget\s+").unwrap(),
        Regex::new(r"(?i)curl\s+.*\|\s*sh").unwrap(),
        Regex::new(r"(?i)union\s+select").unwrap(),
        Regex::new(r"(?i)<script").unwrap(),
        Regex::new(r"(?i)\.\.\/").unwrap(),
    ];
}

#[derive(Serialize)]
pub struct PredictionResult {
    pub score: f64,
    pub label: String,
    pub status: &'static str,
    pub probabilities: Option<HashMap<String, f64>>,
}

pub fn extract_features(
    service: &str,
    username: &str,
    password: &str,
    command: &str,
    source_port: Option<i32>,
    timestamp: DateTime<Utc>,
) -> Vec<f32> {
    let mut f = vec![0.0f32; 10];

    // 1. service_port
    f[0] = match service.to_uppercase().as_str() {
        "SSH" => 22.0,
        "FTP" => 21.0,
        "HTTP" => 80.0,
        "TELNET" => 23.0,
        "SMTP" => 25.0,
        "RDP" => 3389.0,
        _ => 0.0,
    };

    // 2. username_len
    f[1] = username.len() as f32;

    // 3. password_len
    f[2] = password.len() as f32;

    // 4. command_len
    f[3] = command.len() as f32;

    // 5. source_port
    f[4] = source_port.unwrap_or(0) as f32;

    // 6. hour_of_day
    f[5] = timestamp.hour() as f32;

    // 7. dangerous_pattern_count
    let mut count = 0;
    if !command.is_empty() {
        for re in DANGEROUS_RE.iter() {
            if re.is_match(command) {
                count += 1;
            }
        }
    }
    f[6] = count as f32;

    // 8. is_root_user
    let u_lower = username.to_lowercase();
    f[7] = if u_lower == "root" || u_lower == "admin" || u_lower == "administrator" { 1.0 } else { 0.0 };

    // 9. is_anonymous_user
    f[8] = if u_lower == "anonymous" || u_lower == "guest" || u_lower == "visitor" { 1.0 } else { 0.0 };

    // 10. has_command
    f[9] = if !command.trim().is_empty() { 1.0 } else { 0.0 };

    f
}

pub fn predict_lstm(features: &[f32]) -> PredictionResult {
    let score = estimate_threat_score(features);
    let label = if score >= 0.5 { "malicious".to_string() } else { "benign".to_string() };
    PredictionResult {
        score,
        label,
        status: "heuristic-fallback",
        probabilities: None,
    }
}

pub fn predict_rf(features: &[f32]) -> PredictionResult {
    let score = estimate_threat_score(features);
    let label = if score >= 0.7 {
        "malicious".to_string()
    } else if score >= 0.3 {
        "suspicious".to_string()
    } else {
        "benign".to_string()
    };

    let mut probabilities = HashMap::new();
    probabilities.insert("benign".to_string(), (1.0 - score).max(0.0));
    probabilities.insert("suspicious".to_string(), if score >= 0.3 && score < 0.7 { score } else { 0.1 });
    probabilities.insert("malicious".to_string(), if score >= 0.7 { score } else { 0.0 });

    PredictionResult {
        score,
        label,
        status: "heuristic-fallback",
        probabilities: Some(probabilities),
    }
}

fn estimate_threat_score(features: &[f32]) -> f64 {
    let mut base = 0.05;

    // has_command
    if features[9] > 0.0 { base += 0.15; }
    
    // dangerous_pattern_count
    base += (features[6] as f64) * 0.35;
    
    // is_root_user
    if features[7] > 0.0 { base += 0.20; }
    
    // password_len
    if features[2] > 0.0 {
        base += (features[2] as f64 * 0.02).min(0.20);
    }

    base.min(1.0)
}
