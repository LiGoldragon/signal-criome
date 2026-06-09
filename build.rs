use schema_rust_next::build::ContractCrateBuild;

fn main() {
    ContractCrateBuild::from_environment(
        "signal-criome",
        "0.1.0",
        "SIGNAL_CRIOME_UPDATE_SCHEMA_ARTIFACTS",
    )
    .expect_fresh();
}
