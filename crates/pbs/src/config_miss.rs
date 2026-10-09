//! Keys whose bid or preferences requests name none of their relays, because
//! their builder config is missing or stale. Each epoch names the first few
//! keys and counts the rest, so these warnings stay a few lines an epoch and
//! their memory stays bounded.

use std::{
    collections::HashSet,
    sync::{LazyLock, Mutex, PoisonError},
    time::Duration,
};

use cb_common::types::BlsPublicKey;
use tracing::warn;

/// Keys named in the log each epoch
const NAMED: usize = 5;
/// Keys remembered each epoch, so each is counted once
const REMEMBERED: usize = 1024;
/// Auth data bytes logged, since a request can send up to 4096
const AUTH_DATA_SHOWN: usize = 64;

/// Auth data naming none of the key's relays that is not a builder outside the
/// config
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Miss {
    /// It names Commit-Boost itself: no builder config, or an entry without
    /// auth data
    NoConfig,
    /// It names another of Commit-Boost's relays
    Stale,
}

#[derive(Default)]
struct Epoch {
    keys: HashSet<BlsPublicKey>,
    /// Keys past the first few
    unnamed: usize,
    /// Whether keys past `REMEMBERED` went uncounted
    full: bool,
}

static EPOCH: LazyLock<Mutex<Epoch>> = LazyLock::new(Default::default);

/// Whether to name `pubkey`: each epoch names its first few keys and counts
/// the rest, and a key already seen is neither
fn admit(epoch: &mut Epoch, pubkey: &BlsPublicKey) -> bool {
    if epoch.keys.contains(pubkey) {
        return false;
    }
    if epoch.keys.len() == REMEMBERED {
        epoch.full = true;
        return false;
    }
    epoch.keys.insert(pubkey.clone());
    let named = epoch.keys.len() <= NAMED;
    if !named {
        epoch.unnamed += 1;
    }
    named
}

/// Logs how many keys the epoch left unnamed, and starts the next
fn roll(epoch: &mut Epoch) {
    if epoch.unnamed > 0 {
        warn!(
            keys = epoch.unnamed,
            at_least = epoch.full,
            "more keys than logged named none of their relays last epoch; write their builder \
             config with `commit-boost builder-config apply` or your tooling"
        );
    }
    *epoch = Epoch::default();
}

pub(crate) fn record(pubkey: &BlsPublicKey, mux_id: Option<&str>, auth_data: &[u8], miss: Miss) {
    if !admit(&mut EPOCH.lock().unwrap_or_else(PoisonError::into_inner), pubkey) {
        return;
    }
    let mux = mux_id.unwrap_or("[[relays]]");
    let auth_data = String::from_utf8_lossy(&auth_data[..auth_data.len().min(AUTH_DATA_SHOWN)]);
    match miss {
        Miss::NoConfig => warn!(
            %pubkey, mux, ?auth_data,
            "auth data names Commit-Boost itself: the key has no builder config, or an entry \
             without auth_data; write it with `commit-boost builder-config apply` or your tooling"
        ),
        Miss::Stale => warn!(
            %pubkey, mux, ?auth_data,
            "auth data names another of Commit-Boost's relays: the key's builder config is \
             stale; write it again with `commit-boost builder-config apply` or your tooling"
        ),
    }
}

/// Ends an epoch every `epoch_secs`, counted from the service's start
pub(crate) fn start(epoch_secs: u64) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(epoch_secs.max(1)));
        loop {
            tick.tick().await;
            roll(&mut EPOCH.lock().unwrap_or_else(PoisonError::into_inner));
        }
    });
}

#[cfg(test)]
mod tests {
    use cb_common::types::BlsSecretKey;

    use super::*;

    // A key is counted once, the first few are named, and memory stops growing
    // at the cap
    #[test]
    fn an_epoch_names_a_few_and_counts_each_key_once() {
        let mut epoch = Epoch::default();
        let keys: Vec<_> =
            (0..REMEMBERED + 3).map(|_| BlsSecretKey::random().public_key()).collect();
        let named = keys.iter().chain(&keys[..2]).filter(|key| admit(&mut epoch, key)).count();
        assert_eq!(named, NAMED);
        assert_eq!(epoch.keys.len(), REMEMBERED);
        assert_eq!((epoch.unnamed, epoch.full), (REMEMBERED - NAMED, true));
        roll(&mut epoch);
        assert_eq!((epoch.keys.len(), epoch.unnamed, epoch.full), (0, 0, false));
    }

    // An epoch that ends with keys it did not name logs how many
    #[test]
    #[tracing_test::traced_test]
    fn an_epoch_ending_counts_its_unnamed_keys() {
        roll(&mut Epoch { unnamed: 3, ..Default::default() });
        assert!(logs_contain("keys=3"));
        assert!(logs_contain("more keys than logged named none of their relays last epoch"));
    }

    // A request whose auth data names Commit-Boost itself is recorded for the
    // epoch's log
    #[tokio::test]
    async fn a_miss_is_recorded() {
        let pubkey = BlsSecretKey::random().public_key();
        let addressed = crate::utils::Addressed {
            endpoint: "a_miss_is_recorded",
            pubkey: &pubkey,
            mux_id: None,
            all_relays: &[],
        };
        let mut headers = reqwest::header::HeaderMap::new();
        let host = reqwest::header::HeaderValue::from_static("cb.example.com");
        headers.insert(reqwest::header::HOST, host);
        let resolved =
            crate::utils::resolve_addressed_relay(&[], b"cb.example.com", &headers, 0, &addressed);
        assert!(resolved.await.is_err());
        assert!(EPOCH.lock().unwrap_or_else(PoisonError::into_inner).keys.contains(&pubkey));
    }
}
