#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::types::{BinaryDecodable, ContextOwned, Error, Variant};
    use std::io::Cursor;

    pub fn deserialize(data: &[u8]) -> Result<Variant, Error> {
        // Decode this, don't expect panics or whatever
        let mut stream = Cursor::new(data);
        let ctx_f = ContextOwned::default();
        Variant::decode(&mut stream, &ctx_f.context())
    }

    // With some random data, just try and deserialize it. The deserialize should either return
    // a Variant or an error. It shouldn't panic.
    let _ = deserialize(data);
});
