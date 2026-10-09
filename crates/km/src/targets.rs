//! Where builder-config writes: Commit-Boost's URL and the validator clients.

use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use eyre::{Result, bail, ensure};
use url::{Host, Url};

use crate::client::read_token;

#[derive(Debug)]
pub struct Targets {
    /// Commit-Boost's URL as the beacon nodes reach it. Written as given,
    /// since a parsed `Url` gains a trailing slash
    pub advertised_url: String,
    pub vcs: Vec<VcConfig>,
}

#[derive(Debug, Clone)]
pub struct VcConfig {
    /// The validator client's keymanager API
    pub url: Url,
    pub token_path: PathBuf,
}

/// `<keymanager URL>=<token file>`, split at the first `=`: a keymanager URL
/// has none, a file path might
impl FromStr for VcConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((url, token_path)) = s.split_once('=') else {
            return Err(format!("{s}: not <keymanager URL>=<token file>"));
        };
        // `localhost:5062` would parse with the scheme `localhost`
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("{url}: not an http(s) URL"));
        }
        let url = Url::parse(url).map_err(|err| format!("{url}: {err}"))?;
        if token_path.is_empty() {
            return Err(format!("{s}: no token file after ="));
        }
        Ok(Self { url, token_path: token_path.into() })
    }
}

/// Written as typed, so only a form the beacon node reads the same way:
/// `localhost:18550` parses with the scheme `localhost`, and
/// `https:cb.example.com` only once the parser repairs it
pub fn check_advertised_url(url: &str) -> Result<()> {
    ensure!(
        (url.starts_with("http://") || url.starts_with("https://")) &&
            url.trim() == url &&
            Url::parse(url).is_ok(),
        "--advertised-url is not an http(s) URL: {url}"
    );
    Ok(())
}

impl Targets {
    pub fn new(advertised_url: String, vcs: Vec<VcConfig>) -> Result<Self> {
        check_advertised_url(&advertised_url)?;
        let mut seen = BTreeSet::new();
        if let Some(vc) = vcs.iter().find(|vc| !seen.insert(&vc.url)) {
            bail!("{} is given twice with --vc", vc.url);
        }
        for (i, vc) in vcs.iter().enumerate() {
            if let Some(alias) =
                vcs[i + 1..].iter().find(|other| same_loopback(&vc.url, &other.url))
            {
                bail!(
                    "{} and {} are one validator client given twice with --vc",
                    vc.url,
                    alias.url
                );
            }
        }
        Ok(Self { advertised_url, vcs })
    }

    /// Reads every token file, so a bad path stops the run before any client
    /// is contacted
    pub fn check_token_files(&self) -> Result<()> {
        for vc in &self.vcs {
            read_token(&vc.token_path)?;
        }
        Ok(())
    }
}

pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.to_canonical().is_loopback(),
        Some(Host::Domain(host)) => host == "localhost",
        None => false,
    }
}

/// `localhost`, `127.0.0.1` or `[::1]`, the names of one listener; other
/// loopback addresses, such as `127.0.0.2`, are separate sockets
fn localhost_name(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        Some(Host::Domain(host)) => host == "localhost",
        None => false,
    }
}

/// Two localhost names for one port, such as `localhost` and `127.0.0.1`: one
/// client, whose keys would read as held by two
fn same_loopback(a: &Url, b: &Url) -> bool {
    localhost_name(a) &&
        localhost_name(b) &&
        a.scheme() == b.scheme() &&
        a.port_or_known_default() == b.port_or_known_default() &&
        a.path() == b.path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_url_must_be_http() {
        for (url, ok) in [
            ("http://cb.example.com:18550", true),
            ("https://cb.example.com", true),
            ("not a url", false),
            ("localhost:18550", false),
            ("ftp://cb.example.com", false),
            ("https:cb.example.com", false),
            (" http://cb.example.com", false),
            ("http://cb.example.com ", false),
            ("http://", false),
        ] {
            assert_eq!(Targets::new(url.to_string(), vec![]).is_ok(), ok, "{url}");
        }
    }

    // One client twice would read as a key held by two
    #[test]
    fn refuses_a_validator_client_given_twice() {
        for (a, b, refused) in [
            ("http://127.0.0.1:7500", "http://127.0.0.1:7500", true),
            ("http://localhost:7500", "http://127.0.0.1:7500", true),
            ("http://[::1]:7500", "http://127.0.0.1:7500/", true),
            ("http://localhost:7500", "http://127.0.0.1:7501", false),
            ("http://localhost:7500", "https://127.0.0.1:7500", false),
            ("http://10.0.0.1:7500", "http://10.0.0.2:7500", false),
            ("http://10.0.0.1:7500", "http://127.0.0.1:7500", false),
            ("http://127.0.0.1:7500", "http://10.0.0.1:7500", false),
            // A proxy on one port can route two paths to two clients
            ("http://localhost:7500/a", "http://127.0.0.1:7500/b", false),
            // Clients bound to their own loopback addresses
            ("http://127.0.0.1:7500", "http://127.0.0.2:7500", false),
        ] {
            let vc = |url: &str| format!("{url}=/t").parse::<VcConfig>().unwrap();
            let targets = Targets::new("http://cb:18550".to_string(), vec![vc(a), vc(b)]);
            match targets {
                Ok(_) => assert!(!refused, "{a} {b}"),
                Err(err) => {
                    assert!(refused, "{a} {b}");
                    assert!(format!("{err:#}").contains("given twice"), "{err:#}");
                }
            }
        }
    }

    #[test]
    fn vc_flag_parses_url_and_token_file() {
        let vc: VcConfig = "http://127.0.0.1:7500=/run/secrets/a=b".parse().unwrap();
        assert_eq!(
            (vc.url.as_str(), vc.token_path.to_str()),
            ("http://127.0.0.1:7500/", Some("/run/secrets/a=b"))
        );
        for bad in [
            "http://127.0.0.1:7500",
            "http://127.0.0.1:7500=",
            "not a url=/t",
            "localhost:7500=/t",
            "127.0.0.1:7500=/t",
        ] {
            assert!(bad.parse::<VcConfig>().is_err(), "{bad}");
        }
    }
}
