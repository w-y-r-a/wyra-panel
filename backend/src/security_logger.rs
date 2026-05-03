use crate::{OtherBson, database::get_collection, get_ip::IpResponse};
use bson::{doc, DateTime};

#[derive(Debug)]
pub(crate) struct SecurityEvent {
    pub(crate) event_type: String,
    pub(crate) event_desc: String,
    pub(crate) user_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) ip: IpResponse,
    pub(crate) other: Option<Vec<OtherBson>>
}

pub(crate) async fn log_event(e: SecurityEvent) {
    let security_logs_col = get_collection("security_logs").expect("Failed to get security_logs collection");
    
    let mut event_doc = doc! {
        "event_type": e.event_type,
        "event_desc": e.event_desc,
        "user_id": e.user_id,
        "session_id": e.session_id,
        "ip_header": e.ip.header_ip,
        "ip_addr": e.ip.upstream_ip,
        "timestamp": DateTime::now(),
    };
    
    if let Some(other) = e.other {
        for t in other {
            event_doc.insert(t.name, t.field); // puts it into there
        }
    }
    
    let _id = security_logs_col.insert_one(event_doc).await.expect("Failed to log security event").inserted_id;

    tracing::info!(inserted_id=_id.as_object_id().unwrap().to_string(), "Logged Security Event");
}