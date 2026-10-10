use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, LazyLock, OnceLock},
    time::{Duration, Instant},
};

use cb_common::{
    config::{GetHeaderTransport, RelayConfig},
    pbs::{RelayClient, RelayEntry},
    types::BlsPublicKey,
    utils::bls_pubkey_from_hex,
};
use parking_lot::Mutex;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::{sync::Semaphore, task::JoinHandle};
use tracing::{info, warn};
use url::Url;

use crate::error::PbsClientError;

/// The `relay_id` of every dial: the target comes from request data, so a
/// per-host metric label would be unbounded
const DIAL_RELAY_ID: &str = "dial";

/// The BLS12-381 G1 generator, standing in for the pubkey `RelayEntry` requires
/// but only PBS reads. A workaround to leave `RelayClient` unchanged until PBS
/// is deprecated, when the pubkey can go.
static DIAL_PUBKEY: LazyLock<BlsPublicKey> = LazyLock::new(|| {
    bls_pubkey_from_hex(
        "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    )
    .expect("the G1 generator is a valid pubkey")
});

/// The address in auth data, before the first `?`. Parameters after it are
/// for the builder, which gets them inside the signed auth
pub(crate) fn auth_data_address(data: &[u8]) -> &[u8] {
    data.iter().position(|&byte| byte == b'?').map_or(data, |end| &data[..end])
}

/// A relay for the builder an unmatched address names, checked before the dial
/// and, for a hostname, again on each new connection
pub(crate) async fn dial_relay(
    data_url: Option<Url>,
    address: &[u8],
    lookup_timeout: Duration,
) -> Result<RelayClient, PbsClientError> {
    let url = dial_target(data_url, address)?;
    let origin = url.origin().ascii_serialization();
    let addrs = resolve_dial_target(&url, &origin, lookup_timeout).await?;
    info!(%origin, ?addrs, "auth data names a builder outside the config, dialing it");
    dial_client(url)
}

/// `data_url`, else `https://<hostname>/` for the builder-specs default auth
/// data, a bare hostname
fn dial_target(data_url: Option<Url>, address: &[u8]) -> Result<Url, PbsClientError> {
    data_url
        .or_else(|| {
            let url =
                Url::parse(&format!("https://{}/", std::str::from_utf8(address).ok()?)).ok()?;
            // Parsing also takes a port, userinfo, a path, upper case and
            // numeric IPv4, so only a host already in canonical form passes
            (url.host_str()?.as_bytes() == address).then_some(url)
        })
        .ok_or_else(|| {
            warn!(
                address = ?String::from_utf8_lossy(address),
                "auth data matches no configured relay and is neither a hostname nor a URL"
            );
            PbsClientError::AuthDataMismatch
        })
}

/// A lookup that times out keeps its blocking thread until the resolver
/// returns, and relays' own lookups share that pool, so few run at once
static DIAL_LOOKUPS: Semaphore = Semaphore::const_new(32);

async fn resolve_dial_target(
    url: &Url,
    origin: &str,
    lookup_timeout: Duration,
) -> Result<Vec<SocketAddr>, PbsClientError> {
    let host_port = format!(
        "{}:{}",
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default()
    );
    // An IP literal needs no lookup
    if let Ok(addr) = host_port.parse::<SocketAddr>() {
        vet_dial_addrs(origin, &[addr])?;
        return Ok(vec![addr]);
    }
    let Some(lookup) = spawn_lookup(host_port) else {
        warn!(%origin, "too many dial lookups in flight, not dialing");
        return Err(PbsClientError::NoBuilderResponse);
    };
    let addrs = match tokio::time::timeout(lookup_timeout, lookup).await {
        Ok(Ok(Ok(addrs))) => addrs,
        Ok(Ok(Err(err))) => {
            warn!(%origin, %err, "dial target lookup failed, not dialing");
            return Err(PbsClientError::DialTargetBlocked);
        }
        Ok(Err(_)) => return Err(PbsClientError::Internal),
        // Transient, unlike a failed lookup: the builder counts as not answering
        Err(_) => {
            warn!(%origin, ?lookup_timeout, "dial target lookup timed out, not dialing");
            return Err(PbsClientError::NoBuilderResponse);
        }
    };
    vet_dial_addrs(origin, &addrs)?;
    remember_checked(url.host_str().unwrap_or_default(), &addrs);
    Ok(addrs)
}

/// How long a dial check's lookup serves new connections to its host, so the
/// resolver does not repeat it. Short, so a later connection sees a DNS change
const CHECKED_ADDRS_TTL: Duration = Duration::from_secs(2);

/// Each host's checked addresses and when they were resolved
type CheckedAddrs = HashMap<String, (Instant, Vec<SocketAddr>)>;

static CHECKED_ADDRS: LazyLock<Mutex<CheckedAddrs>> = LazyLock::new(Default::default);

/// Kept with port 0, as the resolver's own lookup returns them, so another
/// dial to the host on another port connects to its own. Drops expired entries
fn remember_checked(host: &str, addrs: &[SocketAddr]) {
    let addrs = addrs.iter().map(|addr| SocketAddr::new(addr.ip(), 0)).collect();
    let mut checked = CHECKED_ADDRS.lock();
    checked.retain(|_, (at, _)| at.elapsed() < CHECKED_ADDRS_TTL);
    checked.insert(host.to_owned(), (Instant::now(), addrs));
}

fn recently_checked(host: &str) -> Option<Vec<SocketAddr>> {
    let checked = CHECKED_ADDRS.lock();
    let (at, addrs) = checked.get(host)?;
    (at.elapsed() < CHECKED_ADDRS_TTL).then(|| addrs.clone())
}

/// `None` when every lookup slot is taken
fn spawn_lookup(host_port: String) -> Option<JoinHandle<io::Result<Vec<SocketAddr>>>> {
    let permit = DIAL_LOOKUPS.try_acquire().ok()?;
    Some(tokio::task::spawn_blocking(move || {
        // Held until the lookup returns, which a timeout does not stop
        let _permit = permit;
        host_port.to_socket_addrs().map(Iterator::collect::<Vec<_>>)
    }))
}

/// Every address is checked, since the dial may connect to any of them
fn vet_dial_addrs(origin: &str, addrs: &[SocketAddr]) -> Result<(), PbsClientError> {
    if dial_target_check_enabled() && addrs.iter().any(|addr| ip_is_disallowed(addr.ip())) {
        warn!(%origin, "dial target resolves to a disallowed address, not dialing");
        return Err(PbsClientError::DialTargetBlocked);
    }
    Ok(())
}

/// Dial hosts are chosen by the request, so an idle connection is reused for at
/// most one slot. The pool sweeps at this interval, so it closes within two.
const DIAL_IDLE_TIMEOUT: Duration = Duration::from_secs(12);

/// Lets a builder dialed again reuse its connection. A failed build is not
/// kept, so the next dial tries again.
static DIAL_CLIENT: OnceLock<RelayClient> = OnceLock::new();

/// No proxy, which would resolve the host itself, and no redirects, since one
/// to an IP address would skip the resolver
fn build_dial_client() -> eyre::Result<RelayClient> {
    RelayClient::with_client_builder(
        dial_config(Url::parse("https://dial.invalid/").expect("a valid URL")),
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(DialResolver)
            .pool_idle_timeout(DIAL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(1),
    )
}

/// The shared dial client, addressed to `url`
fn dial_client(url: Url) -> Result<RelayClient, PbsClientError> {
    let shared = match DIAL_CLIENT.get() {
        Some(shared) => shared,
        None => {
            let built = build_dial_client().map_err(|err| {
                warn!(%err, "failed to build the dial client");
                PbsClientError::Internal
            })?;
            DIAL_CLIENT.get_or_init(|| built)
        }
    };
    let mut relay = shared.clone();
    relay.config = Arc::new(dial_config(url));
    Ok(relay)
}

fn dial_config(url: Url) -> RelayConfig {
    RelayConfig {
        entry: RelayEntry { id: DIAL_RELAY_ID.to_string(), pubkey: DIAL_PUBKEY.clone(), url },
        id: None,
        headers: None,
        get_params: None,
        // HTTP only: a stream's connection skips DialResolver's address check
        get_header: GetHeaderTransport::Http,
        enable_timing_games: false,
        target_first_request_ms: None,
        frequency_get_header_ms: None,
        validator_registration_batch_size: None,
    }
}

/// Run for each new connection to a hostname (an IP address skips it): takes
/// the dial check's recent lookup or its own, and refuses a disallowed address
struct DialResolver;

impl Resolve for DialResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = match recently_checked(name.as_str()) {
                Some(addrs) => addrs,
                None => {
                    spawn_lookup(format!("{}:0", name.as_str()))
                        .ok_or("too many dial lookups in flight")?
                        .await??
                }
            };
            vet_dial_addrs(name.as_str(), &addrs)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(feature = "testing-flags")]
thread_local! {
    static SKIP_DIAL_TARGET_CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only: skips the dial target's address check on this thread, so a
/// test can dial a mock builder on loopback
#[cfg(feature = "testing-flags")]
pub fn set_skip_dial_target_check(skip: bool) {
    SKIP_DIAL_TARGET_CHECK.with(|flag| flag.set(skip));
}

fn dial_target_check_enabled() -> bool {
    #[cfg(feature = "testing-flags")]
    {
        !SKIP_DIAL_TARGET_CHECK.with(|flag| flag.get())
    }
    #[cfg(not(feature = "testing-flags"))]
    {
        true
    }
}

/// Anything but public unicast: the special-purpose IPv4 ranges, also as the
/// IPv4 inside a v4-mapped, v4-compatible or NAT64 address, and IPv6 outside
/// 2000::/3 or in its documentation, Teredo and 6to4 ranges
fn ip_is_disallowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_private() ||
                v4.is_loopback() ||
                v4.is_link_local() ||
                v4.is_multicast() ||
                v4.is_documentation() ||
                // std checks these only on nightly: 0.0.0.0/8, 100.64.0.0/10,
                // 192.0.0.0/24, 198.18.0.0/15 and 240.0.0.0/4
                a == 0 ||
                (a == 100 && b & 0xc0 == 0x40) ||
                (a == 192 && b == 0 && c == 0) ||
                (a == 198 && b & 0xfe == 18) ||
                a >= 240
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
            let embedded =
                if nat64 { Some(Ipv4Addr::from_bits(v6.to_bits() as u32)) } else { v6.to_ipv4() };
            match embedded {
                // :: and ::1 land here as 0.0.0.0 and 0.0.0.1
                Some(v4) => ip_is_disallowed(IpAddr::V4(v4)),
                None => {
                    s[0] & 0xe000 != 0x2000 ||
                        (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8)) ||
                        s[0] == 0x2002
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::StatusCode;
    use cb_common::pbs::decode_auth_data_url;

    use super::*;

    // Literal IPs keep the lookup off the network
    #[tokio::test]
    async fn dial_relay_targets() {
        const MISMATCH: &str = "auth data does not match a configured builder";
        const BLOCKED: &str = "dial target does not resolve or resolves to a disallowed address";
        let cases: [(&[u8], Result<&str, &str>); 8] = [
            (b"http://1.1.1.1:8551", Ok("http://1.1.1.1:8551/")),
            (b"1.1.1.1", Ok("https://1.1.1.1/")),
            (b"1.1.1.1?ofac=1", Ok("https://1.1.1.1/")),
            (b"[2606:4700:4700::1111]", Ok("https://[2606:4700:4700::1111]/")),
            (b"10.0.0.1", Err(BLOCKED)),
            (b"1.1.1.1:8551", Err(MISMATCH)),
            (b"ftp://1.1.1.1", Err(MISMATCH)),
            (&[0xde, 0xad], Err(MISMATCH)),
        ];
        for (data, expected) in cases {
            let address = auth_data_address(data);
            let res =
                dial_relay(decode_auth_data_url(address), address, Duration::from_secs(5)).await;
            let case = String::from_utf8_lossy(data);
            match (&res, expected) {
                (Ok(relay), Ok(url)) => {
                    assert_eq!(relay.config.entry.url.as_str(), url, "{case}");
                    assert_eq!(relay.id.as_str(), "dial", "{case}");
                    assert_eq!(relay.config.get_header, GetHeaderTransport::Http, "{case}");
                }
                (Err(err), Err(message)) => assert_eq!(err.to_string(), message, "{case}"),
                _ => panic!("{case}: expected {expected:?}, got {:?}", res.map(|_| ())),
            }
        }
    }

    /// Taken by every test that holds or takes a lookup slot, since the slots
    /// are shared by the whole test binary
    static LOOKUP_SLOTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn lookup_cap_refuses_hostnames_not_ip_literals() {
        let _slots = LOOKUP_SLOTS.lock().await;
        let _held = DIAL_LOOKUPS.try_acquire_many(32).unwrap();
        let dial = |address: &'static [u8]| dial_relay(None, address, Duration::from_secs(1));
        assert!(dial(b"1.1.1.1").await.is_ok());
        assert!(matches!(dial(b"builder.invalid").await, Err(PbsClientError::NoBuilderResponse)));
    }

    #[test]
    fn vet_dial_addrs_checks_every_address() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(matches!(
            vet_dial_addrs("https://builder.example.com", &[
                addr("1.1.1.1:443"),
                addr("10.0.0.1:443")
            ]),
            Err(PbsClientError::DialTargetBlocked)
        ));
    }

    /// A builder on loopback whose `/bid` redirects to `/internal` and whose
    /// `/slow` answers after 50 ms, and its count of accepted connections
    async fn mock_builder() -> eyre::Result<(u16, Arc<AtomicUsize>)> {
        use axum::{Router, http::header::LOCATION, routing::post, serve::ListenerExt};

        let connections = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let accepted = connections.clone();
        let listener = listener.tap_io(move |_| {
            accepted.fetch_add(1, Ordering::Relaxed);
        });
        let builder = Router::new()
            .route(
                "/bid",
                post(|| async { (StatusCode::TEMPORARY_REDIRECT, [(LOCATION, "/internal")]) }),
            )
            .route("/internal", post(|| async { StatusCode::OK }))
            .route(
                "/slow",
                post(|| async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    StatusCode::OK
                }),
            );
        tokio::spawn(async move { axum::serve(listener, builder).await });
        Ok((port, connections))
    }

    // An IP literal skips the resolver, which would refuse loopback
    #[tokio::test]
    async fn dials_share_connections_and_refuse_redirects() -> eyre::Result<()> {
        let (port, connections) = mock_builder().await?;
        let url = Url::parse(&format!("http://127.0.0.1:{port}/bid"))?;
        for _ in 0..2 {
            let res = dial_client(url.clone())?.client.post(url.clone()).send().await?;
            assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        }
        assert_eq!(connections.load(Ordering::Relaxed), 1);

        tokio::time::pause();
        tokio::time::advance(DIAL_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::time::resume();
        dial_client(url.clone())?.client.post(url).send().await?;
        assert_eq!(connections.load(Ordering::Relaxed), 2);
        Ok(())
    }

    // Two requests at once need two connections, and only one stays idle
    #[tokio::test]
    async fn dial_client_keeps_one_idle_connection_per_host() -> eyre::Result<()> {
        let (port, connections) = mock_builder().await?;
        let url = Url::parse(&format!("http://127.0.0.1:{port}/slow"))?;
        let client = dial_client(url.clone())?.client;
        for _ in 0..2 {
            tokio::try_join!(client.post(url.clone()).send(), client.post(url.clone()).send())?;
        }
        assert_eq!(connections.load(Ordering::Relaxed), 3);
        Ok(())
    }

    // No check runs before these dials, so only the resolver refuses
    // `localhost`, which resolves to loopback
    #[cfg(feature = "testing-flags")]
    #[tokio::test]
    async fn dial_client_checks_the_addresses_it_resolves() -> eyre::Result<()> {
        let _slots = LOOKUP_SLOTS.lock().await;
        let (port, _) = mock_builder().await?;
        let url = Url::parse(&format!("http://localhost:{port}/bid"))?;
        let dial = || dial_client(url.clone()).map(|relay| relay.client.post(url.clone()).send());
        assert!(dial()?.await.is_err());
        set_skip_dial_target_check(true);
        let held = DIAL_LOOKUPS.try_acquire_many(32)?;
        assert!(dial()?.await.is_err());
        drop(held);
        let res = dial()?.await;
        set_skip_dial_target_check(false);
        assert_eq!(res?.status(), StatusCode::TEMPORARY_REDIRECT);
        Ok(())
    }

    // With every lookup slot held, the connection can only use the addresses
    // the dial's check resolved
    #[cfg(feature = "testing-flags")]
    #[tokio::test]
    async fn dial_connects_to_the_addresses_its_check_resolved() -> eyre::Result<()> {
        let _slots = LOOKUP_SLOTS.lock().await;
        let (port, _) = mock_builder().await?;
        let url = Url::parse(&format!("http://localhost:{port}/bid"))?;
        set_skip_dial_target_check(true);
        let relay = dial_relay(Some(url.clone()), b"", Duration::from_secs(5)).await?;
        let held = DIAL_LOOKUPS.try_acquire_many(32)?;
        let res = relay.client.post(url).send().await;
        drop(held);
        set_skip_dial_target_check(false);
        // dial_client_checks_the_addresses_it_resolves needs a lookup
        CHECKED_ADDRS.lock().remove("localhost");
        assert_eq!(res?.status(), StatusCode::TEMPORARY_REDIRECT);
        Ok(())
    }

    // A remembered address is checked again before a connection uses it
    #[tokio::test]
    async fn dial_resolver_checks_remembered_addresses() {
        remember_checked("remembered.invalid", &["127.0.0.1:0".parse().unwrap()]);
        let res = DialResolver.resolve("remembered.invalid".parse().unwrap()).await;
        CHECKED_ADDRS.lock().remove("remembered.invalid");
        assert!(res.is_err());
    }

    #[test]
    fn checked_addrs_drop_their_port_expire_and_are_swept() {
        let addrs = ["1.1.1.1:443".parse().unwrap()];
        let expired = Instant::now().checked_sub(CHECKED_ADDRS_TTL).unwrap();
        CHECKED_ADDRS.lock().insert("expired.invalid".into(), (expired, addrs.to_vec()));
        assert_eq!(recently_checked("expired.invalid"), None);
        remember_checked("fresh.invalid", &addrs);
        assert_eq!(recently_checked("fresh.invalid"), Some(vec!["1.1.1.1:0".parse().unwrap()]));
        let mut checked = CHECKED_ADDRS.lock();
        assert!(!checked.contains_key("expired.invalid"));
        checked.remove("fresh.invalid");
    }

    #[test]
    fn ip_is_disallowed_table() {
        for (ip, disallowed) in [
            ("127.0.0.1", true),
            ("0.0.0.0", true),
            ("::1", true),
            ("10.0.0.1", true),
            ("169.254.1.1", true),
            ("255.255.255.255", true),
            ("100.64.0.1", true),
            ("100.127.255.254", true),
            ("100.63.0.1", false),
            ("100.128.0.1", false),
            ("fd12:3456::1", true),
            ("fe80::1", true),
            ("::ffff:127.0.0.1", true),
            ("::10.0.0.1", true),
            ("64:ff9b::a00:5", true),
            ("::1.1.1.1", false),
            ("64:ff9b::1.1.1.1", false),
            ("::ffff:1.1.1.1", false),
            ("0.1.2.3", true),
            ("192.0.1.1", false),
            ("198.19.255.255", true),
            ("198.20.0.1", false),
            ("224.0.0.1", true),
            ("240.0.0.1", true),
            ("192.0.0.192", true),
            ("198.18.0.1", true),
            ("203.0.113.1", true),
            ("fec0::1", true),
            ("ff02::1", true),
            ("2001:db8::1", true),
            ("64:ff9b:1::a00:1", true),
            ("2002:a00:1::1", true),
            ("2001::1", true),
            ("1.1.1.1", false),
            ("2606:4700:4700::1111", false),
        ] {
            assert_eq!(ip_is_disallowed(ip.parse().unwrap()), disallowed, "{ip}");
        }
    }
}
