use pasetors::claims::Claims;
use pasetors::public;
use super::TokenClaims;
use crate::KEY_PAIR;

pub(crate) fn generate_token(claims: TokenClaims) -> String {
    //! Generates a JWT token for the given claims
    let mut claims_struct = Claims::new().expect("Adding current time + 1hr overflowed");
    if let Some(host_uuid) = &claims.host_uuid {
        claims_struct.audience(host_uuid).expect("Failed to add host_uuid");
    }
    claims_struct.subject(&claims.id).expect("Failed to add id/subject");
    claims_struct.add_additional("sid", claims.session_id).expect("Failed to add sid");
    
    let secret = KEY_PAIR.get().expect("KEY_PAIR not initialized").clone().secret;
    let pub_token = public::sign(&secret, &claims_struct, None, Some(b"implicit assertion")).expect("Failed to creat public token");
    
    pub_token
}