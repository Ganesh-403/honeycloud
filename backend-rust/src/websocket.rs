use axum::extract::ws::{Message, WebSocket};
use tokio::sync::broadcast;
use std::sync::Arc;
use serde_json::json;

pub struct WebSocketState {
    pub tx: broadcast::Sender<String>,
}

impl WebSocketState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }
}

pub async fn handle_socket(mut socket: WebSocket, state: Arc<WebSocketState>) {
    let mut rx = state.tx.subscribe();

    loop {
        tokio::select! {
            msg_res = rx.recv() => {
                if let Ok(msg) = msg_res {
                    if socket.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
            }
            client_msg = socket.recv() => {
                match client_msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.contains("\"type\":\"ping\"") {
                            let pong_msg = json!({
                                "type": "pong"
                            }).to_string();
                            if socket.send(Message::Text(pong_msg)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(_)) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}
