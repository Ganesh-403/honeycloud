use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use sqlx::PgPool;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // username
    pub uid: i32,    // user ID
    pub role: String, // OWNER, ADMIN, ANALYST
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
}

pub fn generate_token(username: &str, user_id: i32, role: &str, secret_key: &str, jti: &str, exp_minutes: i64) -> String {
    let now = Utc::now();
    let expiration = now + Duration::minutes(exp_minutes);

    let claims = Claims {
        sub: username.to_string(),
        uid: user_id,
        role: role.to_string(),
        jti: jti.to_string(),
        exp: expiration.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_bytes()),
    )
    .expect("Token generation failed")
}

pub fn decode_token(token: &str, secret_key: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key.as_bytes()),
        &validation,
    )?;
    Ok(token_data.claims)
}

// Axum Extractor for route protection
pub struct AuthenticatedUser {
    pub username: String,
    pub role: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    PgPool: axum::extract::FromRef<S>,
    Config: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = PgPool::from_ref(state);
        let config = Config::from_ref(state);

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Authorization header missing".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid authorization format".to_string()));
        }

        let token = &auth_header[7..];

        let claims = decode_token(token, &config.secret_key)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Token decoding error: {}", e)))?;

        // Check if token is blacklisted
        let blacklisted: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM token_blacklist WHERE jti = $1")
            .bind(&claims.jti)
            .fetch_one(&pool)
            .await
            .unwrap_or((0,));

        if blacklisted.0 > 0 {
            return Err((StatusCode::UNAUTHORIZED, "Token revoked".to_string()));
        }

        Ok(AuthenticatedUser {
            username: claims.sub,
            role: claims.role,
        })
    }
}
