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

    if values.next().is_some() {
        return Err(IpError::NotUnique(header_name.to_string()));
    }

    let ip = first_value
        .to_str()
        .map_err(|_| IpError::HasInvalidCharacters)?
        .parse::<IpAddr>()
        .map_err(|_| IpError::InvalidValue)?;

    Ok(ip)
}

fn get_ip_from_rightmost_value(
    headers: &HeaderMap,
    header_name: &str,
    trusted_count: usize,
) -> Result<IpAddr, IpError> {
    let joined_values = headers
        .get_all(header_name)
        .iter()
        .map(|x| x.to_str().map_err(|_| IpError::HasInvalidCharacters))
        .collect::<Result<Vec<&str>, IpError>>()?
        .join(",");

    if joined_values.is_empty() {
        return Err(IpError::NotPresent(header_name.to_string()))
    }

    // Selecting the first untrusted IP from the right according to:
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For#selecting_an_ip_address
    joined_values
        .rsplit(",")
        .nth(trusted_count - 1)
        .ok_or(IpError::NotEnoughValues {
            found: joined_values.split(",").count(),
            required: trusted_count,
        })?
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| IpError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_unique_header_pass() {
        let header_name = "X-Real-IP";
        let real_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let mut headers = HeaderMap::new();
        headers.insert(header_name, real_ip.to_string().parse().unwrap());

        let ip = get_ip_from_unique_header(&headers, header_name).unwrap();
        assert_eq!(ip, real_ip);
    }

    #[test]
    fn test_unique_header_duplicated() {
        let header_name = "X-Real-IP";
        let real_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let fake_ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        let mut headers = HeaderMap::new();
        headers.insert(header_name, real_ip.to_string().parse().unwrap());
        headers.append(header_name, fake_ip.to_string().parse().unwrap());

        let err = get_ip_from_unique_header(&headers, header_name)
            .expect_err("Not unique header should fail");
        assert!(matches!(err, IpError::NotUnique(_)));
    }
    #[test]
    fn test_unique_header_not_present() {
        let header_name = "X-Real-IP";
        let headers = HeaderMap::new();

        let err = get_ip_from_unique_header(&headers, header_name)
            .expect_err("Missing header should fail");
        assert!(matches!(err, IpError::NotPresent(_)));
    }

    #[test]
    fn test_unique_header_invalid_value() {
        let header_name = "X-Real-IP";
        let mut headers = HeaderMap::new();
        headers.insert(header_name, "invalid-ip".parse().unwrap());

        let err =
            get_ip_from_unique_header(&headers, header_name).expect_err("Invalid IP should fail");
        assert!(matches!(err, IpError::InvalidValue));
    }

    #[test]
    fn test_unique_header_empty_value() {
        let header_name = "X-Real-IP";
        let mut headers = HeaderMap::new();
        headers.insert(header_name, "".parse().unwrap());

        let err =
            get_ip_from_unique_header(&headers, header_name).expect_err("Invalid IP should fail");
        assert!(matches!(err, IpError::InvalidValue));
    }

    #[test]
    fn test_rightmost_header_comma_separated() {
        let header_name = "X-Forwarded-For";
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

        let mut headers = HeaderMap::new();
        headers.insert(header_name, format!("{},{},{}", ip1, ip2, ip3).parse().unwrap());

        let ip = get_ip_from_rightmost_value(&headers, header_name, 1).unwrap();
        assert_eq!(ip, ip3);

        let ip = get_ip_from_rightmost_value(&headers, header_name, 2).unwrap();
        assert_eq!(ip, ip2);

        let ip = get_ip_from_rightmost_value(&headers, header_name, 3).unwrap();
        assert_eq!(ip, ip1);

        let err = get_ip_from_rightmost_value(&headers, header_name, 4)
            .expect_err("Not enough values should fail");
        assert!(matches!(err, IpError::NotEnoughValues { .. }));
    }

    #[test]
    fn test_rightmost_header_comma_space_separated() {
        let header_name = "X-Forwarded-For";
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

        let mut headers = HeaderMap::new();
        headers.insert(header_name, format!("{}, {}, {}", ip1, ip2, ip3).parse().unwrap());

        let ip = get_ip_from_rightmost_value(&headers, header_name, 1).unwrap();
        assert_eq!(ip, ip3);

        let ip = get_ip_from_rightmost_value(&headers, header_name, 2).unwrap();
        assert_eq!(ip, ip2);

        let ip = get_ip_from_rightmost_value(&headers, header_name, 3).unwrap();
        assert_eq!(ip, ip1);

        let err = get_ip_from_rightmost_value(&headers, header_name, 4)
            .expect_err("Not enough values should fail");
        assert!(matches!(err, IpError::NotEnoughValues { .. }));
    }

    #[test]
    fn test_rightmost_header_duplicated() {
        // If the header appears multiple times, they should be joined together
        // as if they were a single value.
        let header_name = "X-Forwarded-For";
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));
        let ip5 = IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5));

        let mut headers = HeaderMap::new();
        headers.insert(header_name, format!("{},{},{}", ip1, ip2, ip3).parse().unwrap());
        headers.append(header_name, format!("{},{}", ip4, ip5).parse().unwrap());

        let ip = get_ip_from_rightmost_value(&headers, header_name, 1).unwrap();
        assert_eq!(ip, ip5);

        let ip = get_ip_from_rightmost_value(&headers, header_name, 5).unwrap();
        assert_eq!(ip, ip1);

        let err = get_ip_from_rightmost_value(&headers, header_name, 6)
            .expect_err("Not enough values should fail");
        assert!(matches!(err, IpError::NotEnoughValues { .. }));
    }

    #[test]
    fn test_rightmost_header_not_present() {
        let header_name = "X-Forwarded-For";
        let headers = HeaderMap::new();

        let err = get_ip_from_rightmost_value(&headers, header_name, 1)
            .expect_err("Missing header should fail");
        assert!(matches!(err, IpError::NotPresent(_)));
    }

    #[test]
    fn test_rightmost_header_invalid_value() {
        let header_name = "X-Forwarded-For";
        let mut headers = HeaderMap::new();
        headers.insert(header_name, "invalid-ip".parse().unwrap());

        let err = get_ip_from_rightmost_value(&headers, header_name, 1)
            .expect_err("Invalid IP should fail");
        assert!(matches!(err, IpError::InvalidValue));
    }
}
