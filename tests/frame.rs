use signal_criome::schema::lib::{ContractMarker, InputRoute, z2VN3L, z2VaZo};

#[test]
fn request_route_and_frame_round_trip_follow_the_generated_interface() {
    let request = z2VN3L::z2VMY4(z2VaZo {});
    assert_eq!(request.route(), InputRoute::ObserveNodePublicKey);

    let exchange = signal_frame::ExchangeIdentifier::new(
        signal_frame::SessionEpoch::new(31),
        signal_frame::ExchangeLane::Connector,
        signal_frame::LaneSequence::first(),
    );
    let encoded = request
        .encode_request_frame(exchange)
        .expect("request frame encodes");
    let (decoded_exchange, decoded) =
        ContractMarker::decode_single_request(&encoded).expect("request frame decodes");
    assert_eq!(decoded_exchange, exchange);
    assert_eq!(decoded.route(), InputRoute::ObserveNodePublicKey);
}
