pub(crate) mod initial_register;
pub(crate) mod login;
pub(crate) mod token_helpers;
pub(crate) mod register;

use serde::{Deserialize, Serialize};
use bson::DateTime;

// Represents a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct User {
    pub(crate) id: String, // UUID for multi-server support,
    pub(crate) username: String,
    pub(crate) disabled: bool,
    pub(crate) name: Option<String>,
    pub(crate) host: Option<String>, // Will be used for multi-server support
    pub(crate) host_uuid: Option<String>, // Will be used for multi-server support, to uniquely identify the server the user is registered on
    pub(crate) password_hash: String, // Argon2 hash of the user's password
    pub(crate) user_created_method: String, // How the user was created, `local` for Local, or plugin-provided.
    pub(crate) groups: Vec<String>, // User groups for permission checks and/or Unix Wheels
}

// Represents a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Session {
    pub(crate) session_id: String,
    pub(crate) id: String, // UUID for multi-server support
    pub(crate) username: String,
    pub(crate) host: Option<String>, // Will be used for multi-server support
    pub(crate) host_uuid: Option<String>, // Will be used for multi-server support, to uniquely identify the server the user is authenticated to,
    pub(crate) expires_at: DateTime,
    pub(crate) issued_at: DateTime,
    pub(crate) last_active_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TokenClaims {
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) host_uuid: Option<String>, // Will be used for multi-server support, to uniquely identify the server the user is authenticated to
}