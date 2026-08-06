#![cfg(feature = "dotos-text")]

use dotos::{Document, DotosDecode, DotosEncode};
use signal_criome::schema::lib::{z2VN3L, z2VXKz};

const CANONICAL: &str = include_str!("../examples/canonical.dotos");

#[test]
fn every_canonical_dotos_root_decodes_as_an_interface_role() {
    let document = Document::parse(CANONICAL).expect("canonical Dotos parses");
    assert_eq!(document.holds_root_objects(), 1);

    for (index, block) in document.root_objects().iter().enumerate() {
        let request = z2VN3L::from_dotos_block(block);
        let reply = z2VXKz::from_dotos_block(block);
        assert!(
            request.is_ok() || reply.is_ok(),
            "canonical root {index} belongs to neither ordinary role: \
             request={request:?}, reply={reply:?}"
        );
        if let Ok(request) = request {
            assert_eq!(request.to_dotos(), "ObserveNodePublicKey.()");
        }
    }
}
