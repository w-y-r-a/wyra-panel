use axum::{
    Json,
    http::{StatusCode, HeaderMap},
    extract::ConnectInfo
};
use std::net::SocketAddr;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use super::{Session, TokenClaims, token_helpers::generate_token};
use crate::{HOST_UUID, HOSTNAME, Other, OtherBson, PanelResponse, database::get_collection, get_ip::{get_ip, IpExtractor}, security_logger::{log_event, SecurityEvent}, PanelResult};
use uuid::Uuid;
use bson::{DateTime, doc, serialize_to_document};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LoginRequest {
    pub(crate) username: String,
    pub(crate) password: String
}

// POST /auth/local/login
pub(crate) async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> PanelResult {
    let users_col = get_collection("users").expect("Failed to load users collection");
    let sessions_col = get_collection("sessions").expect("Failed to load sessions collection");

    // validate user
    let user = match users_col.find_one(doc! {"username": &payload.username}).await.expect("Failed to get user") {
        Some(d) => d,
        None => return Err((StatusCode::NOT_FOUND, 
            PanelResponse { success: false, message: "User not Found".to_string(), other: None
        })),
    };

    if user.get_str("user_created_method").unwrap() != "local" {
        return Err((StatusCode::FORBIDDEN, 
            PanelResponse { success: false, message: "User is not a local user".to_string(), other: None
        }));
    }

    let password_hash = user.get_str("password_hash").unwrap();

    let parsed_hash = PasswordHash::new(&password_hash).expect("Failed to parse password hash");
    let argon2 = Argon2::default();

    match argon2.verify_password(payload.password.as_bytes(), &parsed_hash) {
        Ok(_) => {},
        Err(_) => return Err((StatusCode::UNAUTHORIZED, 
            PanelResponse { success: false, message: "Incorrect Password".to_string(), other: None
        }))
    }
    
    let session_id = Uuid::new_v4().to_string();
    let id = user.get_str("id").expect("Failed to get id from user").to_string();
    let host = HOSTNAME.get().expect("HOSTNAME not initialized.").clone();
    let host_uuid = HOST_UUID.get().expect("HOST_UUID not initialized.").clone();

    // now check if user is disabled
    let disabled = user.get_bool("disabled").expect("key `disabled` is not a boolean!");

    if disabled {
        return Err((StatusCode::FORBIDDEN, 
            PanelResponse { success: false, message: "User is disabled".to_string(), other: None
        }));
    }
    
    let session = Session {
        username: payload.username,
        host: Some(host),
        host_uuid: Some(host_uuid),
        session_id: session_id.clone(),
        id: id.clone(),
        expires_at: DateTime::from_chrono(Utc::now() + Duration::hours(1)),
        issued_at: DateTime::from_chrono(Utc::now()),
        last_active_at: DateTime::from_chrono(Utc::now()),
    };
    
    let session_doc = serialize_to_document(&session).expect("Failed to serialize session");
    sessions_col.insert_one(&session_doc).await.expect("Failed to insert serialized session into sessions collection");
    
    let token_claims = TokenClaims {
        session_id: session.session_id,
        id: session.id,
        host_uuid: session.host_uuid,
    };
    
    let token = generate_token(token_claims, None);
    
    log_event(SecurityEvent {
        event_type: "UserLogin".to_string(),
        event_desc: "User Logged in".to_string(),
        user_id: Some(id),
        session_id: Some(session_id.clone()),
        ip: get_ip(IpExtractor { headers: &headers, addr: &addr }),
        other: Some(vec![
            OtherBson {name: "user_expires_at".to_string(), field: bson::Bson::DateTime(session.expires_at)}
        ])
    }).await;

    return Ok((
        StatusCode::OK,
        PanelResponse { success: true, message: "Success!".to_string(), other: Some(vec![Other {name: "token".to_string(), field: Value::String(token)}]) },
    ))
}