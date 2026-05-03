use chrono::{DateTime, Utc};
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::AsymmetricPublicKey;
use pasetors::{public, Public};
use pasetors::version4::V4;
use pasetors::token::UntrustedToken;
use core::convert::TryFrom;
use super::TokenClaims;
use axum::http::StatusCode;
use crate::{KEY_PAIR, Other, PanelResponse};

pub(crate) fn generate_token(claims: TokenClaims, exp: Option<DateTime<Utc>>) -> String {
    //! Generates a JWT token for the given claims
    //! `exp` is optional, but usually for long-lived API tokens. Can be revoked at any time.

    let mut claims_struct = Claims::new().expect("Adding current time + 1hr overflowed");
    if let Some(host_uuid) = &claims.host_uuid {
        claims_struct.audience(host_uuid).expect("Failed to add host_uuid");
    }
    claims_struct.subject(&claims.id).expect("Failed to add id/subject");
    claims_struct.add_additional("sid", claims.session_id).expect("Failed to add sid");
    if let Some(exp) = exp {
        claims_struct.expiration(&exp.to_rfc3339()).expect("Failed to add expiration");
    }
    
    let secret = KEY_PAIR.get().expect("KEY_PAIR not initialized").clone().secret;
    let pub_token = public::sign(&secret, &claims_struct, None, None).expect("Failed to creat public token");
    
    pub_token
}

pub(crate) fn decode_token(
    public_key: &AsymmetricPublicKey<V4>,
    token: &String
) -> Result<Claims, (StatusCode, PanelResponse)> {
    let validation_rules = ClaimsValidationRules::new();
    let untrusted_token = UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|i| {
            return (
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "Invalid Token".to_string(),
                    other: Some(vec![
                        Other {name: "error".to_string(), field: serde_json::Value::String(i.to_string())}
                    ])
                }
            )
        })?;

    let trusted_token = public::verify(public_key, &untrusted_token, &validation_rules, None, None)
        .map_err(|i| {
            return (
                StatusCode::BAD_REQUEST,
                PanelResponse {
                    success: false,
                    message: "Invalid Token".to_string(),
                    other: Some(vec![
                        Other {name: "error".to_string(), field: serde_json::Value::String(i.to_string())}
                    ])
                }
            )
        })?;

    let claims = trusted_token.payload_claims().unwrap();
    return Ok(claims.clone());
}