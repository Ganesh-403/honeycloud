use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    #[serde(skip_serializing)]
    pub hashed_password: String,
    pub role: String, // OWNER, ADMIN, ANALYST
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct AttackEvent {
    pub id: i64,
    pub service: String,
    pub source_ip: String,
    pub source_port: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub command: Option<String>,
    pub severity: String,
    pub score: Option<f64>,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct AttackerProfile {
    pub id: i32,
    pub ip_address: String,
    pub risk_score: i32,
    pub risk_tier: String,
    pub is_blocked: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub total_events: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct MitreMapping {
    pub id: i32,
    pub event_id: i64,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub confidence: i32,
    pub mapped_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: i32,
    pub username: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: Option<String>,
    pub target: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
pub struct TokenBlacklist {
    pub id: i32,
    pub jti: String,
    pub username: String,
    pub blacklisted_at: DateTime<Utc>,
    pub expiration: DateTime<Utc>,
}
