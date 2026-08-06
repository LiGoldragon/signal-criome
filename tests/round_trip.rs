#![cfg(feature = "dotos-text")]

use dotos::{DotosEncode, DotosSource};
use signal_criome::schema::lib::{z2VN3L, z2VaZo};

#[test]
fn request_round_trips_through_dotos_without_readable_rust_aliases() {
    let request = z2VN3L::z2VMY4(z2VaZo {});
    let text = request.to_dotos();
    assert_eq!(text, "ObserveNodePublicKey.()");
    assert_eq!(
        DotosSource::new(&text)
            .parse::<z2VN3L>()
            .expect("Dotos decodes"),
        request,
    );
}
