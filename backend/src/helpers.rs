// likely all of these will be moved into the plugin crate
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Serialize, Deserialize};
use bson::{Bson, doc, Document};
use serde_json::Value;
use axum::http::HeaderMap;
use crate::database::get_collection;

pub type PanelResult = Result<(StatusCode, PanelResponse), (StatusCode, PanelResponse)>; // looks better

#[derive(Debug, Serialize, Deserialize)]
pub struct PanelResponse {
    pub success: bool,
    pub message: String,
    pub other: Option<Vec<Other>>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Other {
    pub name: String,
    pub field: Value
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OtherBson {
    pub name: String,
    pub field: Bson
}

impl IntoResponse for PanelResponse {
    fn into_response(self) -> axum::response::Response {
        let mut body: serde_json::Map<String, Value> = serde_json::Map::new();
        
        // default vals
        body.insert("success".to_string(), Value::Bool(self.success));
        body.insert("message".to_string(), Value::String(self.message));

        if let Some(other) = self.other {
            for t in other {
                body.insert(t.name, t.field); // puts it into there
            }
        }

        Json(body).into_response()
    }
}

#[allow(dead_code)]
pub fn value_to_bson(value: Value) -> Bson {
    match value {
        Value::Array(a) => Bson::Array(a.into_iter().map(value_to_bson).collect()),
        Value::Bool(b) => Bson::Boolean(b),
        Value::Null => Bson::Null,
        Value::String(s) => Bson::String(s),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Bson::Int64(i)
            } else if let Some(f) = n.as_f64() {
                Bson::Double(f)
            } else {
                Bson::String(n.to_string())
            }
        },
        Value::Object(o) => Bson::Document(o.iter().map(|(k, v)| (k.clone(), value_to_bson(v.clone()))).collect()),
    }
}

// returned from get_user_from_headers
pub struct UserCrossRoads {
    pub user: Document,
    pub session: Document,
}

//extracts the access token from the headers and verifies
pub async fn get_user_from_headers(headers: &HeaderMap) -> Result<UserCrossRoads, (StatusCode, PanelResponse)> {
    let access_token = match headers.get("token") {
        Some(u) => {
            match u.to_str() {
                Ok(u) => u,
                Err(_) => return Err((
                    StatusCode::BAD_REQUEST,
                    PanelResponse {
                        success: false,
                        message: "access_token is not UTF-8".to_string(),
                        other: None
                    }
                ))
            }},
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "No access_token provided. You may want to log in again.".to_string(),
                    other: None
                }
            ))
        }
    }.to_string();

    let claims = crate::auth::token_helpers::decode_token(&crate::KEY_PAIR.get().unwrap().public, &access_token)?;

    let sid = &claims.get_claim("sid");

    if sid.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            PanelResponse {
                success: false,
                message: "Session ID not included in token. You may want to log in again.".to_string(),
                other: None
            }
        ))
    }

    let sid = match sid.unwrap().as_str() {
        Some(s) => s.to_string(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "Subject claim is not a string.".to_string(),
                    other: None
                }
            ))
        }
    };
    let sub = claims.get_claim("sub");

    if sub.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            PanelResponse {
                success: false,
                message: "Subject not included in token. You may want to log in again.".to_string(),
                other: None
            }
        ))
    }

    let sub = match sub.unwrap().as_str() {
        Some(s) => s.to_string(),
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "Subject claim is not a string.".to_string(),
                    other: None
                }
            ))
        }
    };

    let users_col = get_collection("users").expect("Failed to load users collection");
    let user = match users_col.find_one(doc! {"id": &sub}).await.expect("Failed to lookup user") {
        Some(d) => d,
        None => return Err((
            StatusCode::NOT_FOUND,
            PanelResponse {
                success: false,
                message: "User Not Found".to_string(),
                other: None
            }
        ))
    };

    let sessions_col = get_collection("sessions").expect("Failed to load sessions collection");

    let session = match sessions_col.find_one(doc! {"session_id": sid}).await.expect("Failed to lookup user's session") {
        Some(d) => d,
        None => return Err((
            StatusCode::FORBIDDEN,
            PanelResponse {
                success: false,
                message: "Session ID Not found. You may want to log in again.".to_string(),
                other: None
            }
        ))
    };

    return Ok(
        UserCrossRoads { user, session}
    )
}