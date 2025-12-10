use alloy::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    LidoRegistry,
    "src/abi/LidoNORegistry.json"
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    LidoCSMRegistry,
    "src/abi/LidoCSModuleNORegistry.json"
}
