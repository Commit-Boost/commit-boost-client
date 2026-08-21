//! The operational overlay: where/how to apply, kept out of the CB config.
//! Fleet-describing fields stay in the CB mux config; this file carries only
//! the advertised sidecar URL, the VC endpoints, and the per-mux fallbacks for
//! MuxConfig fields this cb-common revision does not carry yet (see mux_ext).

use std::{collections::BTreeMap, path::Path};

use eyre::{Context, Result, ensure};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    /// URL the VCs should send builder requests to (Commit-Boost's endpoint).
    /// Kept as the exact configured string: `Url` round-trip serialization
    /// normalizes (adds a trailing slash) and the entry `url` must stay as
    /// written.
    pub advertised_url: String,
    #[serde(default)]
    pub vcs: Vec<VcConfig>,
    #[serde(default)]
    pub per_mux: BTreeMap<String, PerMuxOverlay>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcConfig {
    pub url: Url,
    pub token_path: String,
    /// Per-VC override of the advertised URL
    pub advertised_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerMuxOverlay {
    pub builder_boost_factor: Option<u64>,
    pub min_bid_gwei: Option<u64>,
}

impl Overlay {
    pub fn parse_str(s: &str) -> Result<Self> {
        let overlay: Self = toml::from_str(s).wrap_err("could not parse overlay TOML")?;
        overlay.validate()?;
        Ok(overlay)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("unable to read overlay file: {path:?}"))?;
        Self::parse_str(&text)
    }

    fn validate(&self) -> Result<()> {
        for url in std::iter::once(&self.advertised_url)
            .chain(self.vcs.iter().filter_map(|vc| vc.advertised_url.as_ref()))
        {
            ensure!(Url::parse(url).is_ok(), "advertised_url is not a valid URL: {url}");
        }
        Ok(())
    }

    /// The advertised URL in effect for one VC.
    pub fn advertised_url_for<'a>(&'a self, vc: &'a VcConfig) -> &'a str {
        vc.advertised_url.as_deref().unwrap_or(&self.advertised_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_overlay() {
        let overlay = Overlay::parse_str(r#"advertised_url = "https://cb.example.com""#).unwrap();
        assert_eq!(overlay.advertised_url, "https://cb.example.com");
        assert!(overlay.vcs.is_empty());
        assert!(overlay.per_mux.is_empty());
    }

    #[test]
    fn parses_full_overlay_and_vc_override() {
        let overlay = Overlay::parse_str(
            r#"
            advertised_url = "https://cb.example.com"

            [[vcs]]
            url = "http://vc1:7500"
            token_path = "/tmp/token1"

            [[vcs]]
            url = "http://vc2:7500"
            token_path = "/tmp/token2"
            advertised_url = "https://cb2.example.com"

            [per_mux.mux1]
            builder_boost_factor = 90
            min_bid_gwei = 10000000
            "#,
        )
        .unwrap();
        assert_eq!(overlay.vcs.len(), 2);
        assert_eq!(overlay.advertised_url_for(&overlay.vcs[0]), "https://cb.example.com");
        assert_eq!(overlay.advertised_url_for(&overlay.vcs[1]), "https://cb2.example.com");
        let per_mux = overlay.per_mux.get("mux1").unwrap();
        assert_eq!(per_mux.builder_boost_factor, Some(90));
        assert_eq!(per_mux.min_bid_gwei, Some(10_000_000));
    }

    #[test]
    fn requires_advertised_url() {
        assert!(Overlay::parse_str("").is_err());
    }

    #[test]
    fn rejects_invalid_advertised_url() {
        assert!(Overlay::parse_str(r#"advertised_url = "not a url""#).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(
            Overlay::parse_str(
                r#"advertised_url = "https://a.com"
typo_field = 1"#
            )
            .is_err()
        );
    }
}
