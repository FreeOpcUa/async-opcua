# Fuzzing async-opcua

We have a few basic fuzz targets, more are welcome.

In order to have the fuzz targets be part of the workspace, and still compile normally, we require a feature `nightly`.

To run the fuzz targets you will need to install [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) along with its dependencies.

You will need a nightly compiler, `rustup default nightly`, then, run the fuzz target with

```
cargo fuzz run [TARGET] --features nightly
```
## Recursion-DoS coverage (finding C1)

`corpus/fuzz_deserialize/` contains seeds that exercise the decoder recursion paths guarded
by `DecodingOptions::depth_lock` (DiagnosticInfo, DataValue<->Variant cycle): a fixed decoder
must return an error at `MAX_DECODING_DEPTH`, never overflow the stack.

To surface recursion/stack-overflow regressions, run the deserialize fuzzers with a constrained
stack, e.g.:

```
RUST_MIN_STACK=262144 cargo +nightly fuzz run fuzz_deserialize -- -max_total_time=120
cargo +nightly fuzz run fuzz_dynamic_struct -- -max_total_time=120
```
