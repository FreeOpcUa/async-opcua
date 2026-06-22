#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

// Feature 017 (T014): NumericRange application (Variant::range_of / set_range_of) is reachable from the
// Read/Write services with attacker-controlled IndexRange + Value. Decode an arbitrary Variant from the
// wire bytes and apply directly-constructed NumericRanges (including hostile shapes the parser would
// normally reject: min>max, huge bounds, wrong rank) — these MUST return an error, never panic, and
// never allocate unboundedly.
#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::types::{BinaryDecodable, ContextOwned, NumericRange, Variant};
    use std::io::Cursor;

    // Read up to four u32s from the front of the input to build the ranges; decode a Variant from the rest.
    let mut nums = [0u32; 4];
    let mut consumed = 0usize;
    for slot in nums.iter_mut() {
        if let Some(chunk) = data.get(consumed..consumed + 4) {
            *slot = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            consumed += 4;
        }
    }
    let body = data.get(consumed..).unwrap_or(&[]);

    let ctx = ContextOwned::default();
    let mut stream = Cursor::new(body);
    let Ok(variant) = Variant::decode(&mut stream, &ctx.context()) else {
        return;
    };

    // A spread of ranges, including deliberately-hostile ones (the application code must tolerate any
    // NumericRange value, even those the BNF parser would never produce).
    let ranges = [
        NumericRange::None,
        NumericRange::Index(nums[0]),
        NumericRange::Range(nums[0], nums[1]), // may be min>=max or huge
        NumericRange::MultipleRanges(vec![
            NumericRange::Range(nums[0], nums[1]),
            NumericRange::Index(nums[2]),
            NumericRange::Range(nums[2], nums[3]),
        ]),
        NumericRange::MultipleRanges(vec![
            NumericRange::Index(nums[0]),
            NumericRange::Index(nums[1]),
        ]),
    ];

    for range in &ranges {
        let _ = variant.range_of(range);
        let mut target = variant.clone();
        let _ = target.set_range_of(range, &variant);
    }
});
