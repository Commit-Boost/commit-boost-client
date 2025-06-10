fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe { std::env::set_var("OUT_DIR", "src/proto") };
    tonic_build::configure().build_server(false).compile_protos(
        &[
            "proto/pb/v1/lister.proto",
            "proto/pb/v1/accountmanager.proto",
            "proto/pb/v1/signer.proto",
        ],
        &["proto/pb/v1", "proto/third-party"],
    )?;
    Ok(())
}
