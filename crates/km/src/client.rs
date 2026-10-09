//! Keymanager API client: key listing and the builder_config endpoints
//! (keymanager-APIs #88), with bearer-token auth.

use std::{collections::BTreeSet, path::Path, time::Duration};

use eyre::{Context, Result, bail, ensure};
use serde::Deserialize;
use url::Url;

use crate::doc::BuilderConfig;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
struct KeystoreEntry {
    validating_pubkey: String,
}

#[derive(Deserialize)]
struct SignerDefinition {
    pubkey: String,
}

#[derive(Deserialize)]
struct ErrorResponse {
    message: String,
}

/// A failed response's status, with the keymanager error `message` when the
/// body has one
async fn failure(resp: reqwest::Response) -> String {
    let status = resp.status();
    resp.json::<ErrorResponse>()
        .await
        .map_or_else(|_| status.to_string(), |body| format!("{status}: {:?}", body.message))
}

#[derive(Debug)]
pub enum SetOutcome {
    Accepted,
    KeyNotFound,
    Forbidden(String),
}

pub struct KmClient {
    http: reqwest::Client,
    base: Url,
    token: String,
}

/// A keymanager API token, read from its file
pub fn read_token(path: &Path) -> Result<String> {
    // The shell expands `~` only at the start of a word, not after `--vc URL=`
    let hint = if path.starts_with("~") { " (use $HOME, not ~, after =)" } else { "" };
    let token = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("unable to read token file {path:?}{hint}"))?;
    let token = token.trim();
    ensure!(!token.is_empty(), "token file {path:?} is empty");
    // An older Prysm token file holds a JWT secret, then the token
    ensure!(!token.contains('\n'), "token file {path:?} has more than one line: regenerate it");
    Ok(token.to_string())
}

/// `Url::join` with an absolute path would drop a base path prefix
fn endpoint(base: &Url, path: &str) -> Result<Url> {
    let base = base.as_str().trim_end_matches('/');
    Url::parse(&format!("{base}{path}")).wrap_err_with(|| format!("invalid endpoint {path}"))
}

impl KmClient {
    pub fn from_token_file(base: Url, token_path: &Path) -> Result<Self> {
        let token = read_token(token_path)?;
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { http, base, token })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        endpoint(&self.base, path)
    }

    /// The client's validator keys, lowercased and each once: its keystores,
    /// plus its remote-signer keys where it serves that route. A client may
    /// list a remote-signer key in both
    pub async fn list_keys(&self) -> Result<BTreeSet<String>> {
        let url = self.endpoint("/eth/v1/keystores")?;
        let resp = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !resp.status().is_success() {
            bail!("keystores: {}", failure(resp).await);
        }
        let keystores: Data<Vec<KeystoreEntry>> =
            resp.json().await.wrap_err("invalid keystores response")?;
        let mut keys: BTreeSet<String> =
            keystores.data.into_iter().map(|k| k.validating_pubkey.to_lowercase()).collect();

        let url = self.endpoint("/eth/v1/remotekeys")?;
        let resp = self.http.get(url).bearer_auth(&self.token).send().await?;
        match resp.status().as_u16() {
            200 => {
                let remote: Data<Vec<SignerDefinition>> =
                    resp.json().await.wrap_err("invalid remotekeys response")?;
                keys.extend(remote.data.into_iter().map(|k| k.pubkey.to_lowercase()));
            }
            // a client without remote signing does not serve the route
            404 => {}
            _ => bail!("remotekeys: {}", failure(resp).await),
        }
        Ok(keys)
    }

    /// The key's builder config, or `None` on a 404
    pub async fn get_builder_config(&self, pubkey: &str) -> Result<Option<BuilderConfig>> {
        let url = self.endpoint(&format!("/eth/v1/validator/{pubkey}/builder_config"))?;
        let resp = self.http.get(url).bearer_auth(&self.token).send().await?;
        match resp.status().as_u16() {
            200 => {
                let body: Data<BuilderConfig> =
                    resp.json().await.wrap_err("invalid builder_config response")?;
                Ok(Some(body.data))
            }
            404 => Ok(None),
            _ => bail!("{}", failure(resp).await),
        }
    }

    pub async fn set_builder_config(
        &self,
        pubkey: &str,
        doc: &BuilderConfig,
    ) -> Result<SetOutcome> {
        let url = self.endpoint(&format!("/eth/v1/validator/{pubkey}/builder_config"))?;
        let resp = self.http.post(url).bearer_auth(&self.token).json(doc).send().await?;
        match resp.status().as_u16() {
            202 => Ok(SetOutcome::Accepted),
            404 => Ok(SetOutcome::KeyNotFound),
            403 => Ok(SetOutcome::Forbidden(failure(resp).await)),
            _ => bail!("{}", failure(resp).await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_keeps_the_base_path() {
        for base in ["https://vc.example/prefix", "https://vc.example/prefix/"] {
            let url = endpoint(&Url::parse(base).unwrap(), "/eth/v1/keystores").unwrap();
            assert_eq!(url.as_str(), "https://vc.example/prefix/eth/v1/keystores");
        }
    }

    // Only a path starting with `~`, which the shell leaves as is after
    // `--vc URL=`, gets the $HOME hint; a token file of whitespace is empty
    #[test]
    fn read_token_errors() {
        let err = |path: &Path| format!("{:#}", read_token(path).unwrap_err());
        assert!(!err(Path::new("/nonexistent/token")).contains("$HOME"));
        let blank = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(blank.path(), " \n").unwrap();
        assert!(err(blank.path()).contains("is empty"));
        std::fs::write(blank.path(), "abcd\nef01\n").unwrap();
        assert!(err(blank.path()).contains("has more than one line"));
    }
}
