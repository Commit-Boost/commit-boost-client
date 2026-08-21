//! Minimal keymanager API client: bearer-token auth, keystores listing and
//! the builder_config endpoints (keymanager-APIs #88).

use std::{path::Path, time::Duration};

use eyre::{Context, Result, bail};
use serde::Deserialize;
use tracing::warn;
use url::Url;

use crate::doc::BuilderConfigDoc;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether a token file mode leaks reads beyond the owner.
#[cfg(unix)]
fn token_mode_overexposed(mode: u32) -> bool {
    mode & 0o044 != 0
}

/// Reads a bearer token file, trimming surrounding whitespace. Warns when the
/// file is group- or world-readable.
pub fn read_token(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path)
            && token_mode_overexposed(meta.permissions().mode())
        {
            warn!("token file {path:?} is group- or world-readable");
        }
    }
    let token = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("unable to read token file: {path:?}"))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("token file {path:?} is empty");
    }
    Ok(token)
}

#[derive(Debug, Deserialize)]
struct KeystoresResponse {
    data: Vec<KeystoreEntry>,
}

#[derive(Debug, Deserialize)]
struct KeystoreEntry {
    validating_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct GetBuilderConfigResponse {
    data: BuilderConfigDoc,
}

/// Result of a builder_config GET
#[derive(Debug)]
pub enum GetConfigOutcome {
    Ok(BuilderConfigDoc),
    NotFound,
}

/// Result of a builder_config POST
#[derive(Debug, PartialEq, Eq)]
pub enum PostOutcome {
    /// 202: stored
    Accepted,
    /// 404: this VC does not hold the key (or does not serve the route)
    KeyNotFound,
    /// 403: the config is file-managed on this VC and cannot be overridden
    ConfigFileManaged,
}

pub struct KmClient {
    http: reqwest::Client,
    base: Url,
    token: String,
}

impl KmClient {
    pub fn new(base: Url, token: String) -> Result<Self> {
        let http = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
        Ok(Self { http, base, token })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        // string concat, not Url::join: an absolute path would drop a base
        // path prefix (https://vc.example/prefix)
        let base = self.base.as_str().trim_end_matches('/');
        Url::parse(&format!("{base}{path}")).wrap_err_with(|| format!("invalid endpoint {path}"))
    }

    /// GET /eth/v1/keystores; returns lowercased validating pubkeys. Doubles
    /// as the auth + keymanager-API preflight.
    pub async fn list_keystores(&self) -> Result<Vec<String>> {
        let url = self.endpoint("/eth/v1/keystores")?;
        let resp = self.http.get(url).bearer_auth(&self.token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            bail!("keystores listing failed on {}: {status}", self.base);
        }
        let body: KeystoresResponse = resp.json().await.wrap_err("invalid keystores response")?;
        Ok(body.data.into_iter().map(|k| k.validating_pubkey.to_lowercase()).collect())
    }

    pub async fn get_builder_config(&self, pubkey: &str) -> Result<GetConfigOutcome> {
        let url = self.endpoint(&format!("/eth/v1/validator/{pubkey}/builder_config"))?;
        let resp = self.http.get(url).bearer_auth(&self.token).send().await?;
        match resp.status().as_u16() {
            200 => {
                let body: GetBuilderConfigResponse =
                    resp.json().await.wrap_err("invalid builder_config response")?;
                Ok(GetConfigOutcome::Ok(body.data))
            }
            404 => Ok(GetConfigOutcome::NotFound),
            status => bail!("builder_config GET for {pubkey} on {} failed: {status}", self.base),
        }
    }

    pub async fn post_builder_config(
        &self,
        pubkey: &str,
        doc: &BuilderConfigDoc,
    ) -> Result<PostOutcome> {
        let url = self.endpoint(&format!("/eth/v1/validator/{pubkey}/builder_config"))?;
        let resp = self.http.post(url).bearer_auth(&self.token).json(doc).send().await?;
        match resp.status().as_u16() {
            202 => Ok(PostOutcome::Accepted),
            404 => Ok(PostOutcome::KeyNotFound),
            403 => Ok(PostOutcome::ConfigFileManaged),
            status => bail!("builder_config POST for {pubkey} on {} failed: {status}", self.base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> KmClient {
        KmClient::new(Url::parse(base).unwrap(), "t".into()).unwrap()
    }

    #[test]
    fn endpoint_preserves_base_path_prefix() {
        let url = client("https://vc.example/prefix").endpoint("/eth/v1/keystores").unwrap();
        assert_eq!(url.as_str(), "https://vc.example/prefix/eth/v1/keystores");
        // trailing slash on the base collapses, no double slash
        let url = client("https://vc.example/prefix/").endpoint("/eth/v1/keystores").unwrap();
        assert_eq!(url.as_str(), "https://vc.example/prefix/eth/v1/keystores");
    }

    #[test]
    fn endpoint_without_prefix_unchanged() {
        let url = client("http://127.0.0.1:5062").endpoint("/eth/v1/keystores").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:5062/eth/v1/keystores");
    }

    #[cfg(unix)]
    #[test]
    fn token_mode_overexposure() {
        assert!(token_mode_overexposed(0o644));
        assert!(token_mode_overexposed(0o640));
        assert!(token_mode_overexposed(0o604));
        assert!(!token_mode_overexposed(0o600));
        assert!(!token_mode_overexposed(0o620));
    }
}
