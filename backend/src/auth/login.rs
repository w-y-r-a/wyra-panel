use axum::{
    Json,
    http::StatusCode
};
use serde::{Deserialize, Serialize};
use super::{Session, TokenClaims, token_helpers::generate_token};
use crate::{HOST_UUID, HOSTNAME, database::get_collection};
use uuid::Uuid;
use bson::{doc, serialize_to_document};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LoginResponse {
    pub(crate) success: bool,
    pub(crate) message: String
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LoginRequest {
    pub(crate) username: String,
    pub(crate) password: String
}

pub(crate) async fn login(
    Json(payload): Json<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    let users_col = get_collection("users").expect("Failed to load users collection");
    let sessions_col = get_collection("sessions").expect("Failed to load sessions collection");

    // validate user
    let user = match users_col.find_one(doc! {"username": &payload.username}).await.expect("Failed to get user") {
        Some(d) => d,
        None => return (StatusCode::NOT_FOUND, Json(
            LoginResponse { success: false, message: "User not Found".to_string() 
        }))
    };

    if user.get_str("user_created_method").unwrap() != "local" {
        return (StatusCode::FORBIDDEN, Json(
            LoginResponse { success: false, message: "User is not a local user".to_string() 
        }))
    }

    let password_hash = user.get_str("password_hash").unwrap();

    let parsed_hash = PasswordHash::new(&password_hash).expect("Failed to parse password hash");
    let argon2 = Argon2::default();

    match argon2.verify_password(payload.password.as_bytes(), &parsed_hash) {
        Ok(_) => {},
        Err(_) => return (StatusCode::NOT_FOUND, Json(
            LoginResponse { success: false, message: "Incorrect Password".to_string() 
        }))
    }
    
    let session_id = Uuid::new_v4().to_string();
    let id = user.get_str("id").expect("Failed to get id from user").to_string();
    let host = HOSTNAME.get().expect("HOSTNAME not initialized.").clone();
    let host_uuid = HOST_UUID.get().expect("HOST_UUID not initialized.").clone();
    
    let session = Session {
        username: payload.username,
        host: Some(host),
        host_uuid: Some(host_uuid),
        session_id,
        id,
    };
    
    let session_doc = serialize_to_document(&session).expect("Failed to serialize session");
    sessions_col.insert_one(session_doc).await.expect("Failed to insert serialized session into sessions collection");
    
    let token_claims = TokenClaims {
        session_id: session.session_id,
        id: session.id,
        host_uuid: session.host_uuid,
    };
    
    let token = generate_token(token_claims);
    
    return (
        StatusCode::OK,
        Json(LoginResponse { success: true, message: token }),
    )
}