use std::any::Any;
use serde_json::{json, Value};
use axum::{
    body::Body,
    response::{IntoResponse, Response},
    Json,
    http::{Request, StatusCode}
};
use tokio::signal;
use tokio::signal::unix::{signal, SignalKind};

use crate::database;

pub(crate) async fn handler_405(
    req: Request<Body>
) -> impl IntoResponse {
    let error_desc = format!("This endpoint does not support the {} method", req.method());
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({
            "error": "MethodNotAllowed",
            "error_description": error_desc
        }))
    )
}

pub(crate) fn handler_500(_err: Box<dyn Any + Send>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "server_error",
            "error_description": "An internal server error has occurred. Please make an issue in the GitHub.",
        })),
    )
        .into_response()
}

pub(crate) async fn root_handler() -> Json<Value> {
    Json(json!(
        {
            "status": "healthy",
            "version": crate::config::PANEL_VERSION.get().unwrap(),
            "service": "wyra-panel"
        }
    ))
}

pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {print!("\n"); tracing::info!("Ctrl+C received; Wyra Panel shutting down..."); shutdown_handler().await;}
        _ = terminate => tracing::info!("SIGTERM received; Wyra Panel shutting down..."),
    }
}

async fn shutdown_handler() {
    database::mongo_shutdown().await;

    tracing::error!("MongoDB Shut Down.");
}