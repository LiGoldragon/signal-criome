use std::process::Command;

#[test]
fn default_runtime_tree_excludes_bootstrap_and_retired_crates() {
    let output = Command::new("cargo")
        .args(["tree", "--edges", "normal", "--no-default-features"])
        .output()
        .expect("run cargo tree");

    assert!(output.status.success(), "status: {:?}", output.status);
    let tree = String::from_utf8(output.stdout).expect("dependency tree");

    for forbidden_crate in [
        "core-ethos",
        "name-table",
        "nota",
        "nota-codec",
        "rust-logos",
        "schema-language",
        "schema-rust",
        "sema-translator",
        "signal-core",
        "signal-sema-translator",
        "structural-codec",
    ] {
        assert!(
            !tree.contains(forbidden_crate),
            "default dependency tree must not contain {forbidden_crate}:\n{tree}"
        );
    }
}

#[test]
fn dotos_text_feature_is_the_only_text_projection_opt_in() {
    let output = Command::new("cargo")
        .args([
            "tree",
            "--edges",
            "normal",
            "--no-default-features",
            "--features",
            "dotos-text",
        ])
        .output()
        .expect("run cargo tree");

    assert!(output.status.success(), "status: {:?}", output.status);
    let tree = String::from_utf8(output.stdout).expect("dependency tree");

    assert!(
        tree.contains("dotos"),
        "dotos-text feature should opt into dotos:\n{tree}"
    );
    for forbidden_crate in ["nota-codec", "signal-core"] {
        assert!(
            !tree.contains(forbidden_crate),
            "dotos-text dependency tree must not contain {forbidden_crate}:\n{tree}"
        );
    }
}

#[test]
fn imported_interfaces_share_the_standard_structural_carrier() {
    fn accepts_standard<Value: signal_standard::schema::lib::WireShape>() {}
    accepts_standard::<signal_criome::schema::lib::z2VUph>();
    accepts_standard::<signal_criome::schema::lib::z2VfEW>();
    accepts_standard::<signal_criome::schema::lib::z2VNo7>();

    let behavior = include_str!("../src/schema/lib/behavior.rs");
    assert!(behavior.contains("pub use signal_standard::schema::lib"));
    assert!(!behavior.contains("pub enum WireValue"));
    assert!(!behavior.contains("pub trait WireShape"));

    assert!(
        signal_criome::bootstrap_manifest::DECLARATION_SEATS
            .iter()
            .any(|seat| seat.spelling == "AuthorizationRequestSlot")
    );
}
