use axum::{
    Json,
    http::StatusCode
};
use serde::{Deserialize, Serialize};
use super::AuthedUser;
use crate::{AppState, HOST_UUID, HOSTNAME, database::get_collection};
use uuid::Uuid;
use bson::{doc, serialize_to_document};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rusty_paseto::prelude::*;

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

    // Start building user
    

    return
}