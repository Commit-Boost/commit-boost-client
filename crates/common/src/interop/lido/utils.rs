use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, U256, address};
use eyre::Context;
use lazy_static::lazy_static;

use crate::{
    interop::lido::types::{
        LidoCSMRegistry::{self, getNodeOperatorSummaryReturn},
        LidoRegistry,
    },
    types::{Chain, HoleskyLidoModule, HoodiLidoModule, MainnetLidoModule},
};

lazy_static! {
    static ref LIDO_REGISTRY_ADDRESSES_BY_MODULE: HashMap<Chain, HashMap<u8, Address>> = {
        let mut map: HashMap<Chain, HashMap<u8, Address>> = HashMap::new();

        // --- Mainnet ---
        let mut mainnet = HashMap::new();
        mainnet.insert(
            MainnetLidoModule::Curated as u8,
            address!("55032650b14df07b85bF18A3a3eC8E0Af2e028d5"),
        );
        mainnet.insert(
            MainnetLidoModule::SimpleDVT as u8,
            address!("aE7B191A31f627b4eB1d4DaC64eaB9976995b433"),
        );
        mainnet.insert(
            MainnetLidoModule::CommunityStaking as u8,
            address!("dA7dE2ECdDfccC6c3AF10108Db212ACBBf9EA83F"),
        );
        mainnet.insert(
            MainnetLidoModule::CuratedV2 as u8,
            address!("Da5F930cE326EB5205085D66c72A4E79d60cB8C1"),
        );
        map.insert(Chain::Mainnet, mainnet);

        // --- Holesky ---
        let mut holesky = HashMap::new();
        holesky.insert(
            HoleskyLidoModule::Curated as u8,
            address!("595F64Ddc3856a3b5Ff4f4CC1d1fb4B46cFd2bAC"),
        );
        holesky.insert(
            HoleskyLidoModule::SimpleDVT as u8,
            address!("11a93807078f8BB880c1BD0ee4C387537de4b4b6"),
        );
        holesky.insert(
            HoleskyLidoModule::Sandbox as u8,
            address!("D6C2ce3BB8bea2832496Ac8b5144819719f343AC"),
        );
        holesky.insert(
            HoleskyLidoModule::CommunityStaking as u8,
            address!("4562c3e63c2e586cD1651B958C22F88135aCAd4f"),
        );
        map.insert(Chain::Holesky, holesky);

        // --- Hoodi ---
        let mut hoodi = HashMap::new();
        hoodi.insert(
            HoodiLidoModule::Curated as u8,
            address!("5cDbE1590c083b5A2A64427fAA63A7cfDB91FbB5"),
        );
        hoodi.insert(
            HoodiLidoModule::SimpleDVT as u8,
            address!("0B5236BECA68004DB89434462DfC3BB074d2c830"),
        );
        hoodi.insert(
            HoodiLidoModule::Sandbox as u8,
            address!("682E94d2630846a503BDeE8b6810DF71C9806891"),
        );
        hoodi.insert(
            HoodiLidoModule::CommunityStaking as u8,
            address!("79CEf36D84743222f37765204Bec41E92a93E59d"),
        );
        hoodi.insert(
            HoodiLidoModule::CuratedV2 as u8,
            address!("87EB69Ae51317405FD285efD2326a4a11f6173b9"),
        );
        map.insert(Chain::Hoodi, hoodi);

        // --- Sepolia --
        let mut sepolia = HashMap::new();
        sepolia.insert(1, address!("33d6E15047E8644F8DDf5CD05d202dfE587DA6E3"));
        map.insert(Chain::Sepolia, sepolia);

        map
    };
}

// Fetching appropiate registry address
pub fn lido_registry_address(chain: Chain, lido_module_id: u8) -> eyre::Result<Address> {
    LIDO_REGISTRY_ADDRESSES_BY_MODULE
        .get(&chain)
        .ok_or_else(|| eyre::eyre!("Lido registry not supported for chain: {chain:?}"))?
        .get(&lido_module_id)
        .copied()
        .ok_or_else(|| {
            eyre::eyre!("Lido module id {:?} not found for chain: {chain:?}", lido_module_id)
        })
}

/// Lido staking modules expose one of two node operator registry interfaces.
///
/// The Community Staking Module and the Curated Module v2
/// (`curated-onchain-v2`) share the CSM interface: `getSigningKeys` returns a
/// flat `bytes` blob and the key total is derived from
/// `getNodeOperatorSummary`. Every other module is a `NodeOperatorsRegistry`
/// (curated v1, SimpleDVT, Sandbox), which returns a struct from
/// `getSigningKeys` and exposes `getTotalSigningKeyCount`.
pub fn uses_csm_registry_interface(chain: Chain, module_id: u8) -> bool {
    match chain {
        Chain::Mainnet => {
            module_id == MainnetLidoModule::CommunityStaking as u8 ||
                module_id == MainnetLidoModule::CuratedV2 as u8
        }
        Chain::Holesky => module_id == HoleskyLidoModule::CommunityStaking as u8,
        Chain::Hoodi => {
            module_id == HoodiLidoModule::CommunityStaking as u8 ||
                module_id == HoodiLidoModule::CuratedV2 as u8
        }
        _ => false,
    }
}

pub fn get_lido_csm_registry<P>(
    registry_address: Address,
    provider: P,
) -> LidoCSMRegistry::LidoCSMRegistryInstance<P>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    LidoCSMRegistry::new(registry_address, provider)
}

pub fn get_lido_module_registry<P>(
    registry_address: Address,
    provider: P,
) -> LidoRegistry::LidoRegistryInstance<P>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    LidoRegistry::new(registry_address, provider)
}

pub async fn fetch_lido_csm_keys_total<P>(
    registry: &LidoCSMRegistry::LidoCSMRegistryInstance<P>,
    node_operator_id: U256,
) -> eyre::Result<u64>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let summary: getNodeOperatorSummaryReturn =
        registry.getNodeOperatorSummary(node_operator_id).call().await?;

    let total_u256 = summary.totalDepositedValidators + summary.depositableValidatorsCount;

    let total_u64 = u64::try_from(total_u256)
        .wrap_err_with(|| format!("total keys ({total_u256}) does not fit into u64"))?;

    Ok(total_u64)
}

pub async fn fetch_lido_module_keys_total<P>(
    registry: &LidoRegistry::LidoRegistryInstance<P>,
    node_operator_id: U256,
) -> eyre::Result<u64>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let total_keys: u64 =
        registry.getTotalSigningKeyCount(node_operator_id).call().await?.try_into()?;

    Ok(total_keys)
}

pub async fn fetch_lido_csm_keys_batch<P>(
    registry: &LidoCSMRegistry::LidoCSMRegistryInstance<P>,
    node_operator_id: U256,
    offset: u64,
    limit: u64,
) -> eyre::Result<Bytes>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let pubkeys = registry
        .getSigningKeys(node_operator_id, U256::from(offset), U256::from(limit))
        .call()
        .await?;

    Ok(pubkeys)
}

pub async fn fetch_lido_module_keys_batch<P>(
    registry: &LidoRegistry::LidoRegistryInstance<P>,
    node_operator_id: U256,
    offset: u64,
    limit: u64,
) -> eyre::Result<Bytes>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let pubkeys = registry
        .getSigningKeys(node_operator_id, U256::from(offset), U256::from(limit))
        .call()
        .await?
        .pubkeys;

    Ok(pubkeys)
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{U256, address},
        providers::ProviderBuilder,
        rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN,
    };
    use url::Url;

    use super::*;
    use crate::{interop::lido::types::LidoRegistry, types::BlsPublicKey};

    #[tokio::test]
    async fn test_lido_registry_address() -> eyre::Result<()> {
        let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
        let provider = ProviderBuilder::new().connect_http(url);

        let registry =
            LidoRegistry::new(address!("55032650b14df07b85bF18A3a3eC8E0Af2e028d5"), provider);

        const LIMIT: usize = 3;
        let node_operator_id = U256::from(1);

        let total_keys: u64 =
            registry.getTotalSigningKeyCount(node_operator_id).call().await?.try_into()?;

        assert!(total_keys > LIMIT as u64);

        let pubkeys = registry
            .getSigningKeys(node_operator_id, U256::ZERO, U256::from(LIMIT))
            .call()
            .await?
            .pubkeys;

        let mut vec = vec![];
        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            vec.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        assert_eq!(vec.len(), LIMIT);

        Ok(())
    }

    #[tokio::test]
    async fn test_lido_csm_registry_address() -> eyre::Result<()> {
        let url = Url::parse("https://ethereum-rpc.publicnode.com")?;
        let provider = ProviderBuilder::new().connect_http(url);

        let registry =
            LidoCSMRegistry::new(address!("dA7dE2ECdDfccC6c3AF10108Db212ACBBf9EA83F"), provider);

        const LIMIT: usize = 3;
        let node_operator_id = U256::from(1);

        let summary = registry.getNodeOperatorSummary(node_operator_id).call().await?;

        let total_keys_u256 = summary.totalDepositedValidators + summary.depositableValidatorsCount;
        let total_keys: u64 = total_keys_u256.try_into()?;

        assert!(total_keys > LIMIT as u64, "expected more than {LIMIT} keys, got {total_keys}");

        let pubkeys =
            registry.getSigningKeys(node_operator_id, U256::ZERO, U256::from(LIMIT)).call().await?;

        let mut vec = Vec::new();
        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            vec.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        assert_eq!(vec.len(), LIMIT, "expected {LIMIT} keys, got {}", vec.len());

        Ok(())
    }

    #[test]
    fn test_lido_curated_v2_registry_address() -> eyre::Result<()> {
        assert_eq!(
            lido_registry_address(Chain::Mainnet, MainnetLidoModule::CuratedV2 as u8)?,
            address!("Da5F930cE326EB5205085D66c72A4E79d60cB8C1")
        );

        assert_eq!(
            lido_registry_address(Chain::Hoodi, HoodiLidoModule::CuratedV2 as u8)?,
            address!("87EB69Ae51317405FD285efD2326a4a11f6173b9")
        );

        // CMv2 shares the CSM read interface, so it must be routed to it
        assert!(uses_csm_registry_interface(Chain::Mainnet, MainnetLidoModule::CuratedV2 as u8));
        assert!(uses_csm_registry_interface(Chain::Hoodi, HoodiLidoModule::CuratedV2 as u8));

        // Curated v1 still uses the NodeOperatorsRegistry interface
        assert!(!uses_csm_registry_interface(Chain::Mainnet, MainnetLidoModule::Curated as u8));
        assert!(!uses_csm_registry_interface(Chain::Hoodi, HoodiLidoModule::Curated as u8));

        // CMv2 is not deployed on Holesky
        assert!(lido_registry_address(Chain::Holesky, 5).is_err());

        Ok(())
    }

    /// Reads the first keys of a CMv2 node operator through the same helpers
    /// the mux loader uses.
    async fn assert_curated_v2_keys(
        rpc_url: &str,
        chain: Chain,
        module_id: u8,
    ) -> eyre::Result<()> {
        let url = Url::parse(rpc_url)?;
        let provider = ProviderBuilder::new().connect_http(url);

        let registry_address = lido_registry_address(chain, module_id)?;
        let registry = get_lido_csm_registry(registry_address, provider);

        const LIMIT: u64 = 3;
        let node_operator_id = U256::ZERO;

        let total_keys = fetch_lido_csm_keys_total(&registry, node_operator_id).await?;

        assert!(total_keys >= LIMIT, "expected at least {LIMIT} keys, got {total_keys}");

        let pubkeys = fetch_lido_csm_keys_batch(&registry, node_operator_id, 0, LIMIT).await?;

        assert_eq!(pubkeys.len(), LIMIT as usize * BLS_PUBLIC_KEY_BYTES_LEN);

        let mut vec = Vec::new();
        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            vec.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        assert_eq!(vec.len(), LIMIT as usize);

        Ok(())
    }

    #[tokio::test]
    async fn test_lido_curated_v2_mainnet_keys() -> eyre::Result<()> {
        assert_curated_v2_keys(
            "https://ethereum-rpc.publicnode.com",
            Chain::Mainnet,
            MainnetLidoModule::CuratedV2 as u8,
        )
        .await
    }

    #[tokio::test]
    async fn test_lido_curated_v2_hoodi_keys() -> eyre::Result<()> {
        assert_curated_v2_keys(
            "https://ethereum-hoodi-rpc.publicnode.com",
            Chain::Hoodi,
            HoodiLidoModule::CuratedV2 as u8,
        )
        .await
    }
}
