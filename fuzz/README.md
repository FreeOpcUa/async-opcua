# Fuzzing async-opcua

We have a few basic fuzz targets, more are welcome.

In order to have the fuzz targets be part of the workspace, and still compile normally, we require a feature `nightly`.

To run the fuzz targets you will need to install [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) along with its dependencies.

You will need a nightly compiler, `rustup default nightly`, then, run the fuzz target with

```
cargo fuzz run [TARGET] --features nightly
```