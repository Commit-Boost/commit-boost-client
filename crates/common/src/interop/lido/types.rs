use alloy::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    LidoRegistry,
    "src/abi/LidoNORegistry.json"
}

// Shared by the Community Staking Module and the Curated Module v2
// (`curated-onchain-v2`), which expose the same node operator read interface.
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    LidoCSMRegistry,
    "src/abi/LidoCSModuleNORegistry.json"
}
