#![no_main]
#![cfg(feature = "nightly")]
use libfuzzer_sys::fuzz_target;

use opcua::types::{BinaryDecodable, ContextOwned, Error, Variant};
use std::io::Cursor;

pub fn deserialize(data: &[u8]) -> Result<Variant, Error> {
    // Decode this, don't expect panics or whatever
    let mut stream = Cursor::new(data);
    let ctx_f = ContextOwned::default();
    Variant::decode(&mut stream, &ctx_f.context())
}

fuzz_target!(|data: &[u8]| {
    // With some random data, just try and deserialize it. The deserialize should either return
    // a Variant or an error. It shouldn't panic.
    let _ = deserialize(data);
});
