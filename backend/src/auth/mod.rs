pub(crate) mod initial_register;
//pub(crate) mod login;

use serde::{Deserialize, Serialize};

// Represents an authenticated user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthedUser {
    pub(crate) username: String,
    pub(crate) host: Option<String>, // Will be used for multi-server support
    pub(crate) host_uuid: Option<String>, // Will be used for multi-server support, to uniquely identify the server the user is authenticated to
    pub(crate) session_id: String, // Unique session ID for tracking and management
}

// Represents a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct User {
    pub(crate) id: String, // UUID for multi-server support,
    pub(crate) username: String,
    pub(crate) name: Option<String>,
    pub(crate) host: Option<String>, // Will be used for multi-server support
    pub(crate) host_uuid: Option<String>, // Will be used for multi-server support, to uniquely identify the server the user is registered on
    pub(crate) password_hash: String, // Argon2 hash of the user's password
    pub(crate) user_created_method: String, // How the user was created, `local` for Local, or plugin-provided.
    pub(crate) groups: Vec<String>, // User groups for permission checks and/or Unix Wheels
}