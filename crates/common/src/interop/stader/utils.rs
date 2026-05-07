use std::collections::HashMap;

use crate::interop::stader::types::StaderRegistry;
use crate::types::{Chain, StaderPool};
use alloy::primitives::{Address, Bytes, U256, address};
use alloy::rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN;
use eyre::ensure;
use lazy_static::lazy_static;

const REGISTRY_CALL_BATCH_SIZE: u64 = 250u64;

lazy_static! {
    static ref STADER_REGISTRY_ADDRESSES_BY_MODULE: HashMap<Chain, HashMap<StaderPool, Address>> = {
        let mut map: HashMap<Chain, HashMap<StaderPool, Address>> = HashMap::new();

        // --- Mainnet ---
        let mut mainnet = HashMap::new();
        mainnet.insert(
            StaderPool::Permissioned,
            address!("af42d795a6d279e9dcc19dc0ee1ce3ecd4ecf5dd"),
        );
        mainnet.insert(
            StaderPool::Permissionless,
            address!("4f4bfa0861f62309934a5551e0b2541ee82fdcf1"),
        );
        map.insert(Chain::Mainnet, mainnet);
        map
    };
}

pub fn stader_registry_address(chain: Chain, stader_pool: StaderPool) -> eyre::Result<Address> {
    crate::interop::stader::utils::STADER_REGISTRY_ADDRESSES_BY_MODULE
        .get(&chain)
        .ok_or_else(|| eyre::eyre!("Stader registry not supported for chain: {chain:?}"))?
        .get(&stader_pool)
        .copied()
        .ok_or_else(|| eyre::eyre!("Stader pool {:?} not found for chain: {chain:?}", stader_pool))
}

pub fn get_stader_registry<P>(
    registry_address: Address,
    provider: P,
) -> StaderRegistry::StaderRegistryInstance<P>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    StaderRegistry::new(registry_address, provider)
}

pub async fn fetch_stader_operator_address<P>(
    registry: &StaderRegistry::StaderRegistryInstance<P>,
    node_operator_id: U256,
) -> eyre::Result<Address>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let operator = registry.operatorStructById(node_operator_id).call().await?;

    ensure!(
        operator.operatorAddress != Address::ZERO,
        "Stader operator {node_operator_id} has zero operator address"
    );

    Ok(operator.operatorAddress)
}

pub async fn fetch_stader_keys_total<P>(
    registry: &StaderRegistry::StaderRegistryInstance<P>,
    node_operator_id: U256,
) -> eyre::Result<u64>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let total_keys: u64 =
        registry.getOperatorTotalKeys(node_operator_id).call().await?.try_into()?;

    Ok(total_keys)
}

pub async fn fetch_stader_keys_batch<P>(
    registry: &StaderRegistry::StaderRegistryInstance<P>,
    operator_address: Address,
    offset: u64,
    limit: u64,
) -> eyre::Result<Bytes>
where
    P: Clone + Send + Sync + 'static + alloy::providers::Provider,
{
    let page_number = (offset / REGISTRY_CALL_BATCH_SIZE) + 1;

    let validators = registry
        .getValidatorsByOperator(
            operator_address,
            U256::from(page_number),
            U256::from(REGISTRY_CALL_BATCH_SIZE),
        )
        .call()
        .await?;

    ensure!(
        validators.len() <= limit as usize,
        "Stader returned more validators than expected in batch, expected at most {limit}, got {}",
        validators.len()
    );

    let mut pubkeys = Vec::with_capacity(validators.len() * BLS_PUBLIC_KEY_BYTES_LEN);

    for validator in validators {
        let pubkey = validator.1;

        ensure!(
            pubkey.len() == BLS_PUBLIC_KEY_BYTES_LEN,
            "unexpected Stader validator pubkey length, expected {}, got {}",
            BLS_PUBLIC_KEY_BYTES_LEN,
            pubkey.len()
        );

        pubkeys.extend_from_slice(pubkey.as_ref());
    }

    Ok(Bytes::from(pubkeys))
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
    use crate::types::BlsPublicKey;

    const MAINNET_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";
    const MAX_OPERATOR_ID_TO_SCAN: u64 = 200;

    fn deserialize_pubkeys(pubkeys: &Bytes) -> eyre::Result<Vec<BlsPublicKey>> {
        ensure!(
            pubkeys.len() % BLS_PUBLIC_KEY_BYTES_LEN == 0,
            "unexpected pubkeys bytes length, expected multiple of {}, got {}",
            BLS_PUBLIC_KEY_BYTES_LEN,
            pubkeys.len()
        );

        let mut keys = Vec::new();

        for chunk in pubkeys.chunks(BLS_PUBLIC_KEY_BYTES_LEN) {
            keys.push(
                BlsPublicKey::deserialize(chunk)
                    .map_err(|_| eyre::eyre!("invalid BLS public key"))?,
            );
        }

        Ok(keys)
    }

    fn mainnet_registry(
        pool: StaderPool,
    ) -> eyre::Result<
        StaderRegistry::StaderRegistryInstance<
            impl alloy::providers::Provider + Clone + Send + Sync + 'static,
        >,
    > {
        let url = Url::parse(MAINNET_RPC_URL)?;
        let provider = ProviderBuilder::new().connect_http(url);

        let registry_address = stader_registry_address(Chain::Mainnet, pool)?;

        Ok(StaderRegistry::new(registry_address, provider))
    }

    async fn find_operator_with_min_keys<P>(
        registry: &StaderRegistry::StaderRegistryInstance<P>,
        min_keys: u64,
    ) -> eyre::Result<(U256, Address, u64)>
    where
        P: Clone + Send + Sync + 'static + alloy::providers::Provider,
    {
        for operator_id in 1..=MAX_OPERATOR_ID_TO_SCAN {
            let operator_id = U256::from(operator_id);

            let total_keys = match fetch_stader_keys_total(registry, operator_id).await {
                Ok(total_keys) => total_keys,
                Err(_) => continue,
            };

            if total_keys < min_keys {
                continue;
            }

            let operator_address = match fetch_stader_operator_address(registry, operator_id).await
            {
                Ok(operator_address) => operator_address,
                Err(_) => continue,
            };

            return Ok((operator_id, operator_address, total_keys));
        }

        eyre::bail!(
            "could not find Stader operator with at least {min_keys} keys in first {MAX_OPERATOR_ID_TO_SCAN} operator ids"
        );
    }

    #[tokio::test]
    async fn test_stader_registry_address() -> eyre::Result<()> {
        assert_eq!(
            stader_registry_address(Chain::Mainnet, StaderPool::Permissioned)?,
            address!("af42d795a6d279e9dcc19dc0ee1ce3ecd4ecf5dd")
        );

        assert_eq!(
            stader_registry_address(Chain::Mainnet, StaderPool::Permissionless)?,
            address!("4f4bfa0861f62309934a5551e0b2541ee82fdcf1")
        );

        assert!(stader_registry_address(Chain::Holesky, StaderPool::Permissioned).is_err());
        assert!(stader_registry_address(Chain::Holesky, StaderPool::Permissionless).is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_stader_permissioned_registry_first_batch() -> eyre::Result<()> {
        let registry = mainnet_registry(StaderPool::Permissioned)?;

        const LIMIT: u64 = 3;

        let (operator_id, operator_address, total_keys) =
            find_operator_with_min_keys(&registry, LIMIT).await?;

        let resolved_operator_address =
            fetch_stader_operator_address(&registry, operator_id).await?;

        assert_eq!(resolved_operator_address, operator_address);

        let fetched_total_keys = fetch_stader_keys_total(&registry, operator_id).await?;

        assert_eq!(fetched_total_keys, total_keys);
        assert!(total_keys >= LIMIT);

        let limit = REGISTRY_CALL_BATCH_SIZE.min(total_keys);

        let pubkeys = fetch_stader_keys_batch(&registry, operator_address, 0, limit).await?;

        let keys = deserialize_pubkeys(&pubkeys)?;

        assert_eq!(keys.len(), limit as usize);

        Ok(())
    }

    #[tokio::test]
    async fn test_stader_permissionless_registry_first_batch() -> eyre::Result<()> {
        let registry = mainnet_registry(StaderPool::Permissionless)?;

        const LIMIT: u64 = 3;

        let (operator_id, operator_address, total_keys) =
            find_operator_with_min_keys(&registry, LIMIT).await?;

        let resolved_operator_address =
            fetch_stader_operator_address(&registry, operator_id).await?;

        assert_eq!(resolved_operator_address, operator_address);

        let fetched_total_keys = fetch_stader_keys_total(&registry, operator_id).await?;

        assert_eq!(fetched_total_keys, total_keys);
        assert!(total_keys >= LIMIT);

        let limit = REGISTRY_CALL_BATCH_SIZE.min(total_keys);

        let pubkeys = fetch_stader_keys_batch(&registry, operator_address, 0, limit).await?;

        let keys = deserialize_pubkeys(&pubkeys)?;

        assert_eq!(keys.len(), limit as usize);

        Ok(())
    }

    #[tokio::test]
    async fn test_stader_permissioned_batch_pagination_matches_contract_page_two()
    -> eyre::Result<()> {
        let registry = mainnet_registry(StaderPool::Permissioned)?;

        let min_keys = REGISTRY_CALL_BATCH_SIZE + 1;

        let (_operator_id, operator_address, total_keys) =
            find_operator_with_min_keys(&registry, min_keys).await?;

        assert!(
            total_keys > REGISTRY_CALL_BATCH_SIZE,
            "expected operator with more than {REGISTRY_CALL_BATCH_SIZE} keys, got {total_keys}"
        );

        let offset = REGISTRY_CALL_BATCH_SIZE;
        let limit = REGISTRY_CALL_BATCH_SIZE.min(total_keys - offset);

        let pubkeys = fetch_stader_keys_batch(&registry, operator_address, offset, limit).await?;

        let keys = deserialize_pubkeys(&pubkeys)?;

        assert_eq!(keys.len(), limit as usize);

        let direct_validators = registry
            .getValidatorsByOperator(
                operator_address,
                U256::from(2),
                U256::from(REGISTRY_CALL_BATCH_SIZE),
            )
            .call()
            .await?;

        assert_eq!(
            direct_validators.len(),
            limit as usize,
            "batch helper and direct Stader page 2 returned different lengths"
        );

        let pubkeys_bytes = pubkeys.as_ref();

        for (index, validator) in direct_validators.iter().enumerate() {
            let expected_pubkey = validator.1.as_ref();

            let start = index * BLS_PUBLIC_KEY_BYTES_LEN;
            let end = start + BLS_PUBLIC_KEY_BYTES_LEN;

            assert_eq!(
                &pubkeys_bytes[start..end],
                expected_pubkey,
                "pubkey mismatch at page 2 index {index}"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_stader_permissioned_first_and_second_batches_do_not_overlap() -> eyre::Result<()>
    {
        let registry = mainnet_registry(StaderPool::Permissioned)?;

        let min_keys = REGISTRY_CALL_BATCH_SIZE + 1;

        let (_operator_id, operator_address, total_keys) =
            find_operator_with_min_keys(&registry, min_keys).await?;

        let first_batch_limit = REGISTRY_CALL_BATCH_SIZE.min(total_keys);

        let first_batch =
            fetch_stader_keys_batch(&registry, operator_address, 0, first_batch_limit).await?;

        let second_batch_limit =
            REGISTRY_CALL_BATCH_SIZE.min(total_keys - REGISTRY_CALL_BATCH_SIZE);

        let second_batch = fetch_stader_keys_batch(
            &registry,
            operator_address,
            REGISTRY_CALL_BATCH_SIZE,
            second_batch_limit,
        )
        .await?;

        let first_keys = deserialize_pubkeys(&first_batch)?;
        let second_keys = deserialize_pubkeys(&second_batch)?;

        assert!(!first_keys.is_empty());
        assert!(!second_keys.is_empty());

        assert_ne!(
            first_keys[0], second_keys[0],
            "first key of page 1 and page 2 should not be the same"
        );

        Ok(())
    }
}
