# Async OPC-UA Core

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This is a command line tool to generate code for use with the async-opcua client and server libraries.

To use, define a [YAML](https://yaml.org/) configuration file with a list of code gen targets, including OPC-UA BSD (Binary Schema Definition) files, XSD (XML Schema Definition) files, and NodeSet2.xml files.

See the [custom-codegen](../samples/custom-codegen/) sample for an example of how this can be done.

See [the sample config](./sample_codegen_config.yml) for documentation of the available configuration options.

## Usage in build scripts

Alternatively, this can be used as part of a build script, writing output to the rust target directory. To use this, add `async-opcua-codegen` as build dependency, then in your `build.rs` do something like

```rust
use opcua_codegen::{CodeGenConfig, run_codegen};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = format!("{}/opcua_generated", out_dir);

    println!("cargo:rerun-if-changed=schemas/My.NodeSet2.xml");
    println!("cargo:rustc-env=OPCUA_GENERATED_DIR={}", target_dir);

    run_codegen(
        &CodeGenConfig { ... },
        std::path::Path::new("./")
    )
}
```

Now, somewhere in your code, (typically a separate module) include the generated code:

```rust
include!(concat!(env!("OPCUA_GENERATED_DIR"), "mod.rs"));
```

See [our codegen tests](../codegen-tests/) for an example of how this can be done.

In the async-opcua library itself  we choose not to do this, because we want to carefully keep track of how generated code changes as we change the codegen module, but it is a perfectly reasonable approach.
