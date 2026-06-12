// Build scripts may not assume a system protoc: the vendored binary keeps
// the build hermetic across containers and CI.
#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: build scripts run single-threaded at this point; no other
    // thread can observe the environment mutation.
    unsafe { std::env::set_var("PROTOC", protoc) };

    // guard.proto: client (orchestrator dials the guard).
    // orchestrator.proto: server (orchestrator's external surface).
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["../proto/guard.proto", "../proto/orchestrator.proto"],
            &["../proto"],
        )?;

    println!("cargo:rerun-if-changed=../proto/guard.proto");
    println!("cargo:rerun-if-changed=../proto/orchestrator.proto");
    Ok(())
}
