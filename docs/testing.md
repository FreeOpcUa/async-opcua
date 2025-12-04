# Testing

## Unit tests

Unit tests should cover at least the following

* All handwritten serializable data types and enums, e.g. NodeId, Variant etc.
* Chunking messages together, handling errors, buffer limits, multiple chunks
* Size limits validation on string, array fields in encoded messages
* OpenSecureChannel, CloseSecureChannel request and response
* Every service set call
* Sign, verify, encrypt and decrypt
* Data change filters
* Event filters
* Subscription state engine
* Bug fixes

Unit tests are part of a normal development cycle and you should ensure adequate coverage of new code with tests that are preferably in the same file as the code being tested.

You can run only the unit tests with, but generally you will just run all tests whenever you need to test the library.

```bash
cargo test --skip integration
```

## Integration testing

Integration tests are all tests that start a server and a client. Each integration test spins up a server on a dynamically allocated port, then connects to it with a fresh client. This means that integration tests are completely isolated. Despite this they largely run in a few seconds total.

Integration tests are found under `lib/tests`.

```bash
cargo test
```

## Fuzz testing

Fuzzing involves feeding deliberately junk / randomized data to the code and
seeing how it copes with it. If it panics or otherwise functions in an uncontrolled fashion then it has exposed an error in the code.

Fuzz testing requires a nightly version of Rust and is [restricted to certain platforms](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html).

Read the link above setup basically involves this:

```bash
rustup install nightly
cargo install cargo-fuzz
```

To run:

```bash
cd opcua/async-opcua
rustup default nightly
cargo fuzz list
cargo fuzz run --features nightly fuzz_deserialize
cargo fuzz run --features nightly fuzz_comms
```

Future candidates for fuzzing might include:

* Chunks
* Crypto / signing / verification of chunks
* ExtensionObject containing junk
* DateTime parsing
* EventFilter
* Browse Paths

We might also want to make the fuzzing "structure aware". This involves implementing or deriving an "Arbitrary" trait on types we want to be randomized. See link above for examples.

## OPC UA test cases

The OPC UA foundation describes tests that servers/clients must pass to implement various profiles or facets. Each is described under the test case links against the facets of each [OPC UA profile](http://opcfoundation-onlineapplications.org/ProfileReporting/index.htm).

These are not performed manually or automatically at present, however much of the functionality they describe is covered by unit / integration tests and of course interoperability testing.

## 3rd party interoperability testing

OPC UA for Rust contains a couple of samples built with 3rd party OPC UA open source implementations for
interoperability testing.

* Node OPC UA - a NodeJS based implementation
* Open62541 - a C based implementation

These can be used in place of the `simple-client` and `simple-server` samples as appropriate:

```bash
cd opcua/node-opcua
npm install 
node server.js 
# OR 
node client.js
```

The idea is to test the Rust `simple-client` against the Node OPC UA server to ensure it works. Or
test the Rust `simple-server` by connecting to it with the Node OPC UA client.

The Open62541 only has a very basic client implementation so far. It requires a C compiler and CMake. Basic setup instructions:

```bash
cd opcua/open62541
cmake -G "Unix Makefiles" -B ./cmake-build -S .
cd cmake-build
make
```

In the future we will build tests that interface with some external library, to verify the correctness of the library.
