use chrono::{DateTime, Utc};
use pasetors::claims::Claims;
use pasetors::public;
use super::TokenClaims;
use crate::KEY_PAIR;

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