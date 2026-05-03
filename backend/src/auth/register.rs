use super::User;
use crate::get_ip::{get_ip, IpExtractor};
use crate::groups::group_helpers::{get_group_info_from_str, GroupInfo};
use crate::helpers::{get_user_from_headers, OtherBson};
use crate::security_logger::{log_event, SecurityEvent};
use crate::{
    database::{
        get_collection,
        is_duplicate_key_error
    },
    PanelResponse,
    PanelResult, HOSTNAME
    ,
    HOST_UUID
};
use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    }, Argon2
};
use axum::{
    extract::ConnectInfo,
    http::HeaderMap,
    http::StatusCode,
    Json
};
use bson::{doc, serialize_to_document};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RegisterRequest {
    pub(crate) username: String,
    pub(crate) name: Option<String>,
    pub(crate) password: String,
    pub(crate) groups: Option<Vec<String>>
}

//POST /auth/local/register
pub(crate) async fn register_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>
) -> PanelResult {
    let user_cross_roads = get_user_from_headers(&headers).await?; // Check if the user is authenticated, and return early if not.

    let user = user_cross_roads.user;
    let groups = user.get_array("groups").expect("Failed to get groups from user").to_vec().iter().map(|g| g.as_str().unwrap().to_string()).collect::<Vec<String>>();

    let mut validated_groups: Vec<Option<GroupInfo>> = vec![];

    for group in groups {
        let group_info = get_group_info_from_str(group).await;
        validated_groups.push(group_info);
    }

    let mut onward = false;

    for group_opt in validated_groups {
        if let Some(group) = group_opt {
            if group.has_permission("core.users.manage.create") {
                onward = true;
                break;
            }
        }
    }

    if !onward {
        return Err((StatusCode::FORBIDDEN, PanelResponse {
            success: false,
            message: "You do not have permission(s) to create users.".to_string(),
            other: None
        }));
    }

    let users_collection = get_collection("users").expect("Failed to get users collection");

    if users_collection.find_one(doc! {"username": &payload.username}).await.unwrap().is_some() {
        return Err((StatusCode::BAD_REQUEST, PanelResponse {
            success: false,
            message: "Username already exists!".to_string(),
            other: None
        }));
    }

    // validate selected groups
    if payload.groups.is_some() {
        for group in payload.groups.clone().unwrap() {
            let group_info = get_group_info_from_str(group.clone()).await;
            if group_info.is_none() {
                return Err((StatusCode::BAD_REQUEST, PanelResponse {
                    success: false,
                    message: format!("Group `{}` does not exist.", group),
                    other: None
                }));
            }
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                PanelResponse {
                    success: false,
                    message: "Failed to hash password".to_string(),
                    other: None,
                }
            ));
        }
    };

    let user_ = User {
        id: Uuid::new_v4().to_string(),
        username: payload.username,
        disabled: false,
        name: payload.name,
        host: Some(HOSTNAME.get().expect("HOSTNAME not initialized.").clone()),
        host_uuid: Some(HOST_UUID.get().expect("HOST_UUID not initialized.").clone()),
        password_hash,
        user_created_method: "local".to_string(),
        groups: payload.groups.unwrap_or_default(),
    };

    let _ = users_collection.insert_one(serialize_to_document(&user_).expect("Failed to serialize user into document")).await.map_err(|e| {
        if is_duplicate_key_error(&e) {
            return (
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "Username already exists! (somehow)".to_string(),
                    other: None
                }
            );
        }

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            PanelResponse {
                success: false,
                message: "Failed to create user".to_string(),
                other: None
            }
        )
    })?;


    // log the event
    log_event(SecurityEvent {
        event_type: "UserRegister".to_string(),
        event_desc: "User Registered by an admin.".to_string(),
        user_id: Some(user.get_str("id").unwrap().to_string()), // who did the action
        session_id: Some(user_cross_roads.session.get_str("session_id").unwrap().to_string()), // session of who did the action
        ip: get_ip(IpExtractor { headers: &headers, addr: &addr }),
        other: Some(vec![
            OtherBson { name: "registered_user_id".to_string(), field: bson::Bson::String(user_.id) },
            OtherBson { name: "registered_username".to_string(), field: bson::Bson::String(user_.username) }
        ]),
    }).await;

    return Ok((
        StatusCode::OK,
        PanelResponse {
            success: true,
            message: "User registered!".to_string(),
            other: None,
        }
    ))
}