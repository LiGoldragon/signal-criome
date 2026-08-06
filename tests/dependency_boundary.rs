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
fn build_tree_has_one_exact_corrected_schema_rust() {
    let output = Command::new("cargo")
        .args(["tree", "--edges", "build", "--no-default-features"])
        .output()
        .expect("run cargo tree");

    assert!(output.status.success(), "status: {:?}", output.status);
    let tree = String::from_utf8(output.stdout).expect("dependency tree");

    assert_eq!(
        tree.matches("schema-rust v0.15.0").count(),
        1,
        "build tree must contain one corrected schema-rust:\n{tree}",
    );
    assert!(
        tree.contains("schema-rust.git?rev=9e36587c85bd69357e9042729ba2df0052799756#9e36587c"),
        "schema-rust must be pinned to the published producer head:\n{tree}",
    );
    assert!(
        !tree.contains("schema-language"),
        "strict bootstrap generation has no schema-language dependency:\n{tree}",
    );
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
