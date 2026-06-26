use schema_rust::build::ContractCrateBuild;

fn main() {
    ContractCrateBuild::from_environment(
        "signal-criome",
        "0.4.0",
        "SIGNAL_CRIOME_UPDATE_SCHEMA_ARTIFACTS",
    )
    .expect_fresh();
}
