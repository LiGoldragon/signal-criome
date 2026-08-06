use std::{env, path::PathBuf};

use schema_rust::build::CargoEthosSourceMetadata;

fn main() {
    println!("cargo:rerun-if-changed=ethos/interface.ethos");
    let crate_root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir set"));
    CargoEthosSourceMetadata::new("signal-criome")
        .publish_owned_source_directory(crate_root.join("ethos"));
}
