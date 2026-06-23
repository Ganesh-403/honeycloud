mod config;
mod models;
mod db;
mod auth;
mod mitre;
mod ml;
mod services;
mod websocket;
mod handlers;
mod honeypots;

use axum::{
    routing::{get, post, put},
    Router,
    http::Method,
};
use tower_http::{
    cors::{CorsLayer, Any},
    services::{ServeDir, ServeFile},
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::{establish_connection, init_db};
use crate::websocket::WebSocketState;
use crate::handlers::AppState;
use crate::honeypots::start_honeypots;

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();

    // 1. Configuration & Env Variables
    let config = Config::from_env();
    println!("Starting Honey Cloud Platform in Rust (Production-Grade)...");

    // 2. Database Connection Pool
    let pool = establish_connection(&config).await;
    init_db(&pool).await;

    // 3. Shared State
    let ws_state = Arc::new(WebSocketState::new());
    let state = Arc::new(AppState {
        pool: pool.clone(),
        config: config.clone(),
        ws_state: ws_state.clone(),
    });

    // 4. Start Honeypots background tasks
    start_honeypots(pool.clone(), config.clone(), ws_state.clone());

    // 5. REST API routes
    let api_routes = Router::new()
        // Auth
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/me", get(handlers::me))
        
        // Events & Websocket Ingest
        .route("/events/ingest", post(handlers::ingest_event_api))
        .route("/events", get(handlers::list_events))
        .route("/events/ws", get(handlers::event_ws))

        // Analytics
        .route("/analytics/summary", get(handlers::get_summary))
        .route("/analytics/timeline", get(handlers::get_timeline))
        .route("/analytics/geo", get(handlers::get_geo))
        .route("/analytics/heatmap", get(handlers::get_heatmap))
        .route("/analytics/credentials", get(handlers::get_credentials))
        .route("/analytics/service-trend", get(handlers::get_service_trend))

        // Attacker Profiles
        .route("/profiles", get(handlers::list_profiles))
        .route("/profiles/summary", get(handlers::get_profiles_summary))
        .route("/profiles/:ip", get(handlers::get_profile))
        .route("/profiles/:ip/block", post(handlers::block_profile))
        .route("/profiles/:ip/unblock", post(handlers::unblock_profile))

        // MITRE ATT&CK
        .route("/mitre/techniques", get(handlers::get_mitre_techniques))
        .route("/mitre/stats", get(handlers::get_mitre_stats))
        .route("/mitre/event/:event_id", get(handlers::get_mitre_event))

        // ML Engine
        .route("/ml/status", get(handlers::get_ml_status))
        .route("/ml/train", post(handlers::train_lstm))
        .route("/ml/train-rf", post(handlers::train_rf))
        .route("/ml/predict", post(handlers::predict_lstm_api))
        .route("/ml/predict-rf", post(handlers::predict_rf_api))

        // Reports
        .route("/reports/generate", post(handlers::generate_report))
        .route("/reports/download", get(handlers::download_report))

        // Simulations & Audits
        .route("/simulate", post(handlers::simulate_events))
        .route("/audit", get(handlers::get_audit_logs))

        // Users
        .route("/users", get(handlers::list_users).post(handlers::create_user))
        .route("/users/:id/deactivate", put(handlers::deactivate_user))
        .route("/users/:id/activate", put(handlers::activate_user));

    // Healthcheck endpoint
    let health_route = Router::new().route("/health", get(move || async { "{\"status\":\"ok\"}" }));

    // Serving frontend files statically
    let serve_dir = ServeDir::new("static")
        .not_found_service(ServeFile::new("static/index.html"));

    // Unified router
    let app = Router::new()
        .nest("/api/v1", api_routes)
        .merge(health_route)
        .fallback_service(serve_dir)
        .layer(
            CorsLayer::new()
                .allow_origin(Any) // Or map config allowed origins
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers(Any)
        )
        .with_state(state);

    // 6. Bind Server on 0.0.0.0:8000
    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    println!("Web API server serving static UI and REST controllers at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
