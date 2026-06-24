#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::types::xml::{XmlDecodable, XmlStreamReader};
    use opcua::types::{ContextOwned, DataValue, Variant};
    use std::io::{Cursor, Read};

    // The XML decode path is separate from both the binary and JSON paths and previously had no
    // fuzz coverage. Arbitrary bytes fed to the XML reader must yield a value or an error, never
    // a panic.
    let ctx = ContextOwned::default();

    {
        let mut cursor = Cursor::new(data);
        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
        let _: Result<Variant, _> = XmlDecodable::decode(&mut reader, &ctx.context());
    }
    {
        let mut cursor = Cursor::new(data);
        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
        let _: Result<DataValue, _> = XmlDecodable::decode(&mut reader, &ctx.context());
    }
});
