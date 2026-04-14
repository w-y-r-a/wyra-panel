// Modules
mod config;
mod axum_stuff;
mod database;

// Imports
use std::fmt;
use axum::{
    Router,
    routing::{any}
};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_appender::non_blocking::WorkerGuard;
use chrono::Local;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use std::net::SocketAddr;

const PORT: u32 = 9080;

#[tokio::main]
async fn main() {
    println!("Wyra Panel Starting...");
    let _logging_guard = init_logging(); // _logging_guard keeps the guard alive 
    //for the entire application.
    tracing::info!("Logging initialized!");
    config::init_config();
    tracing::info!("Config initialized!");
    database::mongo_connect().await.expect("MongoDB Connection Failed: ");

    let app = Router::new()
        // Handlers
        .route("/", any(axum_stuff::root_handler))
        
        .method_not_allowed_fallback(axum_stuff::handler_405)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::custom(axum_stuff::handler_500))
        )
        .into_make_service_with_connect_info::<SocketAddr>();
    
    tracing::info!("Starting Wyra Panel on port {}", PORT);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", PORT)).await.expect("Failed to bind to port: ");
    tracing::info!(version = config::PANEL_VERSION.get().unwrap(), "Started Wyra Panel...");
    axum::serve(listener, app)
        .with_graceful_shutdown(axum_stuff::shutdown_signal())
        .await.expect("Failed to start axum");
}

// -------
// Logging
struct ChronoTimer;

impl FormatTime for ChronoTimer {
    //! Formats the Time for tracing
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let now = Local::now();
        write!(w, "{}", now.format("%Y-%m-%d %H:%M:%S"))
    }
}

fn init_logging() -> WorkerGuard {
    // If the log directory doesn't exist, create it in the current
    // working dir.
    init_panic_logging();
    std::fs::create_dir_all("log")
        .expect("Failed to create log directory");
    let log_level =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    let filter = EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let file_appender = rolling::never("./log", format!("wp-backend-{}.log", chrono::Utc::now().to_rfc3339()));
    let (file_writer, guard) =
        tracing_appender::non_blocking(file_appender);

    let stdout_layer = layer()
        .with_timer(ChronoTimer)
        .with_level(true)
        .with_target(true)
        .with_ansi(true)
        .compact();

    let file_layer = layer()
        .with_timer(ChronoTimer)
        .with_level(true)
        .with_target(true)
        .with_ansi(false)
        .with_writer(file_writer)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    guard
}

fn init_panic_logging() {
    std::panic::set_hook(Box::new(|info: &std::panic::PanicHookInfo| {
        tracing_panic::panic_hook(info); // lets tracing give panic
    }));
}

// -------

