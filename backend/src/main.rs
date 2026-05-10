// Modules
mod config;
mod axum_stuff;
mod database;
mod core;
mod auth;
mod get_ip;
mod security_logger;
mod helpers;
mod groups;
mod user;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use axum::response::Response;
use axum::{
    Router,
    routing::{any, post},
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
use hostname::get as hostname_get;
use once_cell::sync::OnceCell;
use tokio::fs::{File, self as tokio_fs};
use serde::{Serialize, Deserialize};
use openssl::pkey::{PKey, Id};
use pasetors::keys::{Generate, AsymmetricKeyPair, AsymmetricSecretKey, AsymmetricPublicKey};
use pasetors::version4::V4;
use axum::{
    extract::ConnectInfo,
    extract::Request,
    middleware::Next,
    body::Body
};
use bson::doc;
use crate::get_ip::IpExtractor;
use crate::groups::group_helpers::init_permissions;
// re-exports
use crate::helpers::*;

static HOSTNAME: OnceCell<String> = OnceCell::new();
static HOST_UUID: OnceCell<String> = OnceCell::new();
static KEY_PAIR: OnceCell<AsymmetricKeyPair<V4>> = OnceCell::new();
static AVAILABLE_PERMISSIONS: OnceCell<HashMap<String, String>> = OnceCell::new(); // Loaded from plugins.
// Also, the hashmap is there because the permissions also need a description for the list

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetupComplete {
    first_register: bool
}

impl fmt::Display for SetupComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"{{ "first_register": {} }}"#, self.first_register)
    }
}

impl Default for SetupComplete {
    fn default() -> Self {
        tracing::warn!("setup_completion.json not found, using default");
        Self { first_register: false }
    }
}

impl SetupComplete {
    fn write_to_disk(&self) {
        fs::write("setup_completion.json", self.to_string()).expect("Failed to write changes");
    }
    fn read_from_disk() -> Self {
        let contents = fs::read_to_string("setup_completion.json").unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
struct AppState {
    setup_complete: Arc<Mutex<SetupComplete>> // arc so multiple threads can access it
}

const PORT: u32 = 9080; // planning to replace this with an env variable

#[tokio::main]
async fn main() {
    println!("Wyra Panel Starting...");
    let _logging_guard = init_logging(); // _logging_guard keeps the guard alive 
    // for the entire application.
    tracing::info!("Logging initialized!");
    tracing::info!("Hello {}!", get_hostname());
    let _ = HOST_UUID.set(set_or_get_host_uuid().await);
    config::init_config();
    tracing::info!("Config initialized!");
    database::mongo_connect().await.expect("MongoDB Connection Failed: ");
    database::set_indexes().await;
    create_and_set_paseto_keys();
    init_permissions();

    let state = AppState { setup_complete: Arc::new(Mutex::new(SetupComplete::read_from_disk())) };

    let app = Router::new()
        // Handlers
        .route("/", any(axum_stuff::root_handler))
        .route("/auth/local/init_register", post(auth::initial_register::initial_register_handler))
        .route("/auth/local/login", post(auth::login::login))
        .route("/auth/local/register", post(auth::register::register_handler))
        .route("/groups/view", post(groups::list::view_groups_handler))

        .method_not_allowed_fallback(axum_stuff::handler_405)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::custom(axum_stuff::handler_500))
        )
        .layer(axum::middleware::from_fn(middleware_one))
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();
    
    tracing::info!("Starting Wyra Panel on port {}", PORT);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", PORT)).await.expect("Failed to bind to port: ");
    tracing::info!(version = config::PANEL_VERSION.get().unwrap(), "Started Wyra Panel...");
    axum::serve(listener, app)
        .with_graceful_shutdown(axum_stuff::shutdown_signal())
        .await.expect("Failed to start axum");
}

// Middleware to check for user
async fn middleware_one(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let req_id = uuid::Uuid::new_v4();
    let ip = get_ip::get_ip(IpExtractor { headers: req.headers(), addr: &addr });
    let uri = req.uri().to_string();
    let next = next.run(req).await;
    tracing::info!(req_id = &req_id.to_string(), header_ip = &ip.header_ip, upstream_ip = &ip.upstream_ip, path=uri, status_code=&next.status().as_u16(), "Incoming request!");

    return next
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

fn get_hostname() -> &'static str {
    HOSTNAME.get_or_init(|| {
        hostname_get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| {tracing::warn!("No Hostname!"); "unknown".to_string()})
    })
}

async fn set_or_get_host_uuid() -> String {
    let file = File::open("host_uuid-DONT-DELETE-OR-MODIFY.txt").await;
    let uuid = match file {
        Ok(mut f) => {
            let mut contents = String::new();
            tokio::io::AsyncReadExt::read_to_string(&mut f, &mut contents).await.expect("Failed to read host UUID file: ");
            let _ = HOST_UUID.set(contents.trim().to_string());
            tracing::info!("Using existing host UUID: {}", contents.trim());
            contents.trim().to_string()
        },
        Err(_) => {
            let new_uuid = uuid::Uuid::new_v4().to_string();
            tracing::warn!("No host UUID found, generating new one: {}", new_uuid);
            tokio_fs::write("host_uuid-DONT-DELETE-OR-MODIFY.txt", &new_uuid).await.expect("Failed to write host UUID file: ");
            let _ = HOST_UUID.set(new_uuid.clone());
            new_uuid
        }
    };
    return uuid;
}

// creates (if not already exists) and sets the paseto key
fn create_and_set_paseto_keys() {
    match fs::File::open("keys/private.pem") {
        Err(_) => {
            tracing::warn!("`keys/private.pem` not found, generating key pair.");
            let key_pair = AsymmetricKeyPair::generate().unwrap();
            // blocking intentionally

            fs::create_dir("keys").unwrap();
            fs::File::create("keys/private.pem").expect("failed to create `keys/private.pem`").write(secret_key_to_pem(&key_pair.secret).as_bytes()).unwrap();
            fs::File::create("keys/public.pem").expect("failed to create `keys/public.pem`").write(public_key_to_pem(&key_pair.public).as_bytes()).unwrap();

            // change file permissions to 0600
            fs::File::set_permissions(&fs::File::open("keys/private.pem").expect("failed to open `keys/private.pem"), fs::Permissions::from_mode(0o600)).expect("Failed to set permissions on private key file");

            KEY_PAIR.set(key_pair).expect("Failed to set KEY_PAIR with key_pair");
        }
        Ok(mut secret_file) => {
            #[allow(unused)]
            let mut public_file = fs::File::open("keys/public.pem").expect("`keys/private.pem` exists, but `keys/public.pem` doesn't.\n Solution: Delete the keys/ directory.");
            tracing::info!("Public and Private key found!");
            #[allow(unused)]
            let mut secret_key = String::new();
            #[allow(unused)]
            let mut public_key = String::new();

            secret_file.read_to_string(&mut secret_key).expect("keys/private.pem is not UTF-8");
            public_file.read_to_string(&mut public_key).expect("keys/public.pem is not UTF-8");

            let secret_key = pem_to_private_key(secret_key);
            let public_key = pem_to_public_key(public_key);

            let key_pair = AsymmetricKeyPair::<V4> {public: public_key, secret: secret_key};

            KEY_PAIR.set(key_pair).expect("Failed to set KEY_PAIR with key_pair");
        }
    }
}

fn pem_to_public_key(pem: String) -> AsymmetricPublicKey<V4> {
    let pkey = PKey::public_key_from_pem(pem.as_bytes()).expect("Invalid Public PEM File!");

    let raw_bytes = pkey.raw_public_key().unwrap();

    let bytes_array: [u8; 32] = raw_bytes.as_slice().try_into()
        .map_err(|_| "Public key is not the expected 32 bytes for Ed25519").unwrap();

    let public_key = AsymmetricPublicKey::<V4>::from(&bytes_array).unwrap();
    public_key
}

fn pem_to_private_key(pem: String) -> AsymmetricSecretKey<V4> {
    let pkey = PKey::private_key_from_pem(pem.as_bytes()).expect("Invalid Private PEM File!");

    let seed_raw = pkey.raw_private_key().expect("Failed to extract raw private key bytes");
    let seed_bytes: [u8; 32] = seed_raw.as_slice().try_into()
        .map_err(|_| "Private key is not the expected 32-byte Ed25519 seed").unwrap();

    let public_raw = pkey.raw_public_key().expect("Failed to extract raw public key bytes");
    let public_bytes: [u8; 32] = public_raw.as_slice().try_into()
        .map_err(|_| "Public key is not the expected 32 bytes for Ed25519").unwrap();

    let mut pasetors_secret = [0u8; 64];
    pasetors_secret[..32].copy_from_slice(&seed_bytes);
    pasetors_secret[32..].copy_from_slice(&public_bytes);

    let private_key = AsymmetricSecretKey::<V4>::from(&pasetors_secret)
        .expect("Failed to create private key from bytes");
    private_key
}


fn public_key_to_pem(public_key: &AsymmetricPublicKey<V4>) -> String {
    let pub_bytes = public_key.as_bytes();

    let pkey = PKey::public_key_from_raw_bytes(pub_bytes, Id::ED25519)
        .expect("Failed to create PKey from bytes");

    let pem_bytes = pkey.public_key_to_pem()
        .expect("Failed to generate PEM");

    String::from_utf8(pem_bytes).expect("Invalid UTF-8 generated")
}

fn secret_key_to_pem(secret_key: &AsymmetricSecretKey<V4>) -> String {
    // pasetors secret key bytes are 64 bytes (seed + public key) for v4/Ed25519.
    // OpenSSL's Ed25519 raw private key constructor expects only the 32-byte seed.
    let secret_bytes = secret_key.as_bytes();
    let seed_bytes = &secret_bytes[..32];

    let pkey = PKey::private_key_from_raw_bytes(seed_bytes, Id::ED25519)
        .expect("Failed to create PKey from seed bytes");

    let pem_bytes = pkey.private_key_to_pem_pkcs8()
        .expect("Failed to generate PKCS#8 PEM");

    String::from_utf8(pem_bytes).expect("Invalid UTF-8 generated")
}