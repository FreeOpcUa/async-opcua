#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::types::json::{JsonDecodable, JsonStreamReader};
    use opcua::types::{ContextOwned, DataValue, Variant};
    use std::io::{Cursor, Read};

    // The JSON decode path is entirely separate from the binary one and has had edge bugs
    // (features 018/019). Arbitrary JSON bytes must yield a value or an error, never a panic.
    let ctx = ContextOwned::default();

    {
        let mut cursor = Cursor::new(data);
        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        let _: Result<Variant, _> = JsonDecodable::decode(&mut reader, &ctx.context());
    }
    {
        let mut cursor = Cursor::new(data);
        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        let _: Result<DataValue, _> = JsonDecodable::decode(&mut reader, &ctx.context());
    }
});
