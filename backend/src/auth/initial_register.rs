use std::net::SocketAddr;

use axum::{
    Json, extract::{ConnectInfo, State}, http::{HeaderMap, StatusCode}
};
use serde::{Deserialize, Serialize};
use super::User;
use argon2::{
    Argon2, password_hash::{
        PasswordHasher, SaltString
    }
};
use rand::rngs::OsRng;
use crate::{AppState, HOST_UUID, HOSTNAME, database::{get_collection, is_duplicate_key_error}, get_ip::{get_ip, IpExtractor}, security_logger::{SecurityEvent, log_event}};
use uuid::Uuid;
use bson::serialize_to_document;

// When Wyra Panel is first setup
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct InitialRegisterRequest {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) name: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct InitialRegisterResponse {
    pub(crate) success: bool,
    pub(crate) message: String
}

// POST /auth/local/init_register
pub(crate) async fn initial_register_handler(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(payload): Json<InitialRegisterRequest>
) -> (StatusCode, Json<InitialRegisterResponse>) {

    // Check if setup is already complete
    {
        let setup = state.setup_complete.lock().unwrap();
        if setup.first_register {
            return (StatusCode::BAD_REQUEST, Json(InitialRegisterResponse {
                success: false,
                message: "Initial registration has already been completed.".to_string()
            }));
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(InitialRegisterResponse {
                success: false,
                message: "Failed to hash password".to_string()
            }));
        }
    };

    let id = Uuid::new_v4().to_string();

    let user = User {
        id,
        disabled: false,
        username: payload.username,
        password_hash,
        user_created_method: "local".to_string(),
        name: payload.name,
        host: HOSTNAME.get().cloned(),
        host_uuid: HOST_UUID.get().cloned(),
        groups: vec!["admin".to_string()] // First user is always an admin
    };

    let users_collection = get_collection("users").expect("Failed to get users collection");
    
    crate::groups::setup_admin::create_admin_group().await;
    
    match users_collection.insert_one(serialize_to_document(&user).expect("Failed to serialize user into document")).await {
        Ok(_) => {
            {
                let mut setup = state.setup_complete.lock().expect("Failed to lock setup_complete");
                setup.first_register = true; // Mark setup as complete
                setup.write_to_disk();
            }

            log_event(SecurityEvent {
                event_type: "InitialRegister".to_string(),
                event_desc: "First User registered as admin".to_string(),
                user_id: Some(user.id),
                session_id: None,
                ip: get_ip(IpExtractor { headers: &headers, addr: &addr }),
                other: None
            }).await;

            (StatusCode::OK, Json(InitialRegisterResponse {
                success: true,
                message: "User registered successfully".to_string()
            }))
        }
        Err(e) => {
            if is_duplicate_key_error(&e) {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(InitialRegisterResponse {
                    success: false,
                    message: "Username already exists (you may need to check your database, this is first register)".to_string()
                }));
            }
            (StatusCode::INTERNAL_SERVER_ERROR, Json(InitialRegisterResponse {
                success: false,
                message: "Failed to register user".to_string()
            }))
        }
    }
}