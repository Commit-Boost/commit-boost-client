use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use cb_common::config::ReverseProxyHeaderSetup;

#[derive(Debug, thiserror::Error)]
pub enum IpError {
    #[error("header `{0}` is not present")]
    NotPresent(String),
    #[error("header value has invalid characters")]
    HasInvalidCharacters,
    #[error("header value is not a valid IP address")]
    InvalidValue,
    #[error("header `{0}` appears multiple times but expected to be unique")]
    NotUnique(String),
}

/// Get the true client IP from the request headers or fallback to the socket
/// address
pub fn get_true_ip(
    headers: &HeaderMap,
    addr: &SocketAddr,
    reverse_proxy: &ReverseProxyHeaderSetup,
) -> Result<IpAddr, IpError> {
    match reverse_proxy {
        ReverseProxyHeaderSetup::None => Ok(addr.ip()),
        ReverseProxyHeaderSetup::Unique(header) => get_ip_from_unique_header(headers, header),
        ReverseProxyHeaderSetup::Rightmost(header) => get_ip_from_rightmost_value(headers, header),
    }
}

fn get_ip_from_unique_header(headers: &HeaderMap, header_name: &str) -> Result<IpAddr, IpError> {
    let mut values = headers.get_all(header_name).iter();

    let first_value = values.next().ok_or(IpError::NotPresent(header_name.to_string()))?;
    let ip = first_value
        .to_str()
        .map_err(|_| IpError::HasInvalidCharacters)?
        .parse::<IpAddr>()
        .map_err(|_| IpError::InvalidValue)?;

    if values.next().is_some() {
        return Err(IpError::NotUnique(header_name.to_string()));
    }

    Ok(ip)
}

fn get_ip_from_rightmost_value(headers: &HeaderMap, header_name: &str) -> Result<IpAddr, IpError> {
    let last_value = headers
        .get_all(header_name)
        .iter()
        .last()
        .ok_or(IpError::NotPresent(header_name.to_string()))?
        .to_str()
        .map_err(|_| IpError::HasInvalidCharacters)?;

    last_value
        .rsplit_once(",")
        .map(|(_, rightmost)| rightmost)
        .unwrap_or(last_value)
        .parse::<IpAddr>()
        .map_err(|_| IpError::InvalidValue)
}
