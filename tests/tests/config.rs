use cb_common::{config::CommitBoostConfig, types::Chain};

#[tokio::test]
async fn test_load_config() {
    let config = CommitBoostConfig::from_file("../config.example.toml");

    assert_eq!(config.chain, Chain::Holesky);
    assert!(config.relays[0].headers.is_some())
    // TODO: add more
}
