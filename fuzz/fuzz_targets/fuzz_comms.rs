#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;

    use opcua::core::comms::tcp_codec::TcpCodec;
    use opcua::types::DecodingOptions;
    // With some random data, just try and deserialize it
    let decoding_options = DecodingOptions::default();
    let mut codec = TcpCodec::new(decoding_options);
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
