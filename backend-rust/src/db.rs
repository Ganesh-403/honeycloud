use sqlx::postgres::{PgPool, PgPoolOptions};
use bcrypt::{hash, DEFAULT_COST};
use crate::config::Config;
use crate::models::User;
use chrono::Utc;

pub async fn establish_connection(config: &Config) -> PgPool {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL")
}

pub async fn init_db(pool: &PgPool) {
    // 1. Create tables
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            hashed_password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL,
            last_login TIMESTAMPTZ
        );"
    ).execute(pool).await.expect("Failed to create users table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS attack_events (
            id BIGSERIAL PRIMARY KEY,
            service VARCHAR(50) NOT NULL,
            source_ip VARCHAR(100) NOT NULL,
            source_port INT,
            timestamp TIMESTAMPTZ NOT NULL,
            username VARCHAR(255),
            password VARCHAR(255),
            command TEXT,
            severity VARCHAR(50) NOT NULL,
            score DOUBLE PRECISION,
            label VARCHAR(50)
        );"
    ).execute(pool).await.expect("Failed to create attack_events table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS attacker_profiles (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(100) UNIQUE NOT NULL,
            risk_score INT NOT NULL DEFAULT 0,
            risk_tier VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
            is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            total_events INT NOT NULL DEFAULT 0
        );"
    ).execute(pool).await.expect("Failed to create attacker_profiles table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mitre_mappings (
            id SERIAL PRIMARY KEY,
            event_id BIGINT NOT NULL,
            technique_id VARCHAR(50) NOT NULL,
            technique_name VARCHAR(255) NOT NULL,
            tactic VARCHAR(255) NOT NULL,
            confidence INT NOT NULL,
            mapped_at TIMESTAMPTZ NOT NULL
        );"
    ).execute(pool).await.expect("Failed to create mitre_mappings table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            action VARCHAR(100) NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL,
            client_ip VARCHAR(100),
            target VARCHAR(255),
            description TEXT
        );"
    ).execute(pool).await.expect("Failed to create audit_logs table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS token_blacklist (
            id SERIAL PRIMARY KEY,
            jti VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) NOT NULL,
            blacklisted_at TIMESTAMPTZ NOT NULL,
            expiration TIMESTAMPTZ NOT NULL
        );"
    ).execute(pool).await.expect("Failed to create token_blacklist table");

    // 2. Seed Default Users if table is empty
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    if count.0 == 0 {
        println!("Database empty. Seeding default roles and credentials...");
        seed_user(pool, "owner", "owner123", "OWNER").await;
        seed_user(pool, "admin", "admin123", "ADMIN").await;
        seed_user(pool, "analyst", "analyst123", "ANALYST").await;
    }
}

async fn seed_user(pool: &PgPool, user: &str, pass: &str, role: &str) {
    let hashed = hash(pass, DEFAULT_COST).expect("Password hashing failed");
    sqlx::query(
        "INSERT INTO users (username, hashed_password, role, is_active, created_at)
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user)
    .bind(hashed)
    .bind(role)
    .bind(true)
    .bind(Utc::now())
    .execute(pool)
    .await
    .expect("Failed to seed default user");
    println!("Seeded default user '{}' with role '{}'", user, role);
}
