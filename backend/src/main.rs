// Modules
mod config;

// Imports
use std::fmt;
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
use tracing_futures::Instrument;
use chrono::Local;


fn main() {
    println!("Wyra Panel Starting...");
    let _logging_guard = init_logging(); // _logging_guard keeps the guard alive 
    //for the entire application.
    tracing::info!("Logging initialized!");
    crate::config::init_config();
    tracing::info!("Config initialized!");

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

    let file_appender = rolling::never("./log", "app.log");
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

