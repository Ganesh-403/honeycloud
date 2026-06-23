use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub secret_key: String,
    pub jwt_expiration_minutes: i64,
    pub rate_limit_per_minute: u32,
    pub telegram_alerts_enabled: bool,
    pub telegram_bot_token: String,
    pub telegram_chat_id: String,
    pub email_alerts_enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub email_from: String,
    pub email_to: String,
    pub geoip_timeout_seconds: u64,
    pub abuseipdb_api_key: String,
    pub reports_dir: String,
    pub ssh_honeypot_port: u16,
    pub ftp_honeypot_port: u16,
    pub http_honeypot_port: u16,
    pub telnet_honeypot_port: u16,
    pub smtp_honeypot_port: u16,
    pub rdp_honeypot_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://honeycloud:honeycloud@localhost:5432/honeycloud".to_string()),
            secret_key: env::var("SECRET_KEY")
                .unwrap_or_else(|_| "default-secret-key-must-be-very-long-and-strong-32-chars-minimum".to_string()),
            jwt_expiration_minutes: env::var("JWT_EXPIRATION_MINUTES")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            telegram_alerts_enabled: env::var("TELEGRAM_ALERTS_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            telegram_bot_token: env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default(),
            telegram_chat_id: env::var("TELEGRAM_CHAT_ID").unwrap_or_default(),
            email_alerts_enabled: env::var("EMAIL_ALERTS_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            smtp_host: env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".to_string()),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            smtp_user: env::var("SMTP_USER").unwrap_or_default(),
            smtp_password: env::var("SMTP_PASSWORD").unwrap_or_default(),
            email_from: env::var("EMAIL_FROM").unwrap_or_default(),
            email_to: env::var("EMAIL_TO").unwrap_or_default(),
            geoip_timeout_seconds: env::var("GEOIP_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            abuseipdb_api_key: env::var("ABUSEIPDB_API_KEY").unwrap_or_default(),
            reports_dir: env::var("REPORTS_DIR").unwrap_or_else(|_| "reports".to_string()),
            ssh_honeypot_port: env::var("SSH_HONEYPOT_PORT")
                .unwrap_or_else(|_| "2222".to_string())
                .parse()
                .unwrap_or(2222),
            ftp_honeypot_port: env::var("FTP_HONEYPOT_PORT")
                .unwrap_or_else(|_| "2121".to_string())
                .parse()
                .unwrap_or(2121),
            http_honeypot_port: env::var("HTTP_HONEYPOT_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            telnet_honeypot_port: env::var("TELNET_HONEYPOT_PORT")
                .unwrap_or_else(|_| "2323".to_string())
                .parse()
                .unwrap_or(2323),
            smtp_honeypot_port: env::var("SMTP_HONEYPOT_PORT")
                .unwrap_or_else(|_| "2525".to_string())
                .parse()
                .unwrap_or(2525),
            rdp_honeypot_port: env::var("RDP_HONEYPOT_PORT")
                .unwrap_or_else(|_| "3389".to_string())
                .parse()
                .unwrap_or(3389),
        }
    }
}
