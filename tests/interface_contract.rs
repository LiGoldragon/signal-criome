use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn strict_ethos_admission_witness_has_one_complete_interface_transaction() {
    let root = root();
    let source =
        fs::read_to_string(root.join("ethos/interface.ethos")).expect("strict Interface exists");
    let binding =
        fs::read_to_string(root.join("src/schema/lib/binding.rs")).expect("binding exists");

    assert!(source.starts_with("Interface.{1 0 0}\n[]\n{"));
    assert_eq!(source.matches("Interface.{").count(), 1);
    assert_eq!(source.matches("\n[]\n{").count(), 1);
    assert!(source.ends_with("}\n"));
    assert!(source.contains("CriomeRequest.["));
    assert!(source.contains("CriomeReply.["));
    assert!(binding.starts_with(
        "// Strict checked-in Rust binding for the authority-verified Criome Interface."
    ));
    assert!(!binding.contains("CriomeRequest"));
    assert!(!binding.contains("CriomeReply"));
}
