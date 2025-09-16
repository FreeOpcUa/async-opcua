# Async OPC-UA Core

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This is a command line tool to generate code for use with the async-opcua client and server libraries.

To use, define a [YAML](https://yaml.org/) configuration file with a list of code gen targets, including OPC-UA BSD (Binary Schema Definition) files, XSD (XML Schema Definition) files, and NodeSet2.xml files.

See the [custom-codegen](../samples/custom-codegen/) sample for an example of how this can be done.

See [the sample config](./sample_codegen_config.yml) for documentation of the available configuration
options.
