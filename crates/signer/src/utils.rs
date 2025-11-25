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
    #[error("header does not contain enough values: found {found}, required {required}")]
    NotEnoughValues { found: usize, required: usize },
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
        ReverseProxyHeaderSetup::Unique { header } => get_ip_from_unique_header(headers, header),
        ReverseProxyHeaderSetup::Rightmost { header, trusted_count } => {
            get_ip_from_rightmost_value(headers, header, trusted_count.get())
        }
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

fn get_ip_from_rightmost_value(
    headers: &HeaderMap,
    header_name: &str,
    trusted_count: usize,
) -> Result<IpAddr, IpError> {
    let last_value = headers
        .get_all(header_name)
        .iter()
        .next_back()
        .ok_or(IpError::NotPresent(header_name.to_string()))?
        .to_str()
        .map_err(|_| IpError::HasInvalidCharacters)?;

    // Selecting the first untrusted IP from the right according to:
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#selecting_an_ip_address
    last_value
        .rsplit(",")
        .nth(trusted_count - 1)
        .ok_or(IpError::NotEnoughValues {
            found: last_value.split(",").count(),
            required: trusted_count,
        })?
        .parse::<IpAddr>()
        .map_err(|_| IpError::InvalidValue)
}
