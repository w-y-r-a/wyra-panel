use std::{
    net::SocketAddr
};
use axum::http::{HeaderMap, HeaderValue};

#[derive(Debug)]
pub(crate) struct IpExtractor<'a> {
    pub(crate) headers: &'a HeaderMap,
    pub(crate) addr: &'a SocketAddr
}

// X-Real-IP or something.
#[derive(Debug)]
pub(crate) struct IpResponse {
    pub(crate) header_ip: String,
    pub(crate) upstream_ip: String
}

pub(crate) fn get_ip(data: IpExtractor) -> IpResponse {
    let default = &HeaderValue::from_str(&data.addr.to_string()).unwrap();

    let x_real_ip = data.headers.get("x-real-ip")
        .unwrap_or(default);

    return IpResponse { header_ip: x_real_ip.to_str().unwrap().to_string(), upstream_ip: data.addr.to_string() }
}