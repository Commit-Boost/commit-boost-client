fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(false).compile_protos(
        &["proto/dirk/lister.proto", "proto/dirk/accountmanager.proto", "proto/dirk/signer.proto"],
        &["proto/dirk", "proto/third-party"],
    )?;
    Ok(())
}
