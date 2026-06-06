# This is a fork, what has changed?

This library is a fork of [opcua](https://github.com/locka99/opcua), due to lack of active maintainers on that project. The following is a nonexhaustive list of the changes:

 * The main interfaces are now async. If you create a server you define async callbacks, and if you use a client you call async methods. If you need blocking logic you are strongly encouraged to handle that yourself, as it is easy to run into issues if you mix async and sync code.
 * We no longer depend on OpenSSL.
 * The library is split into multiple smaller libraries for composability and compile times.
 * A large part of code gen for types is now done with macros, only the actual type definitions (mostly) are generated code.
 * `ExtensionObject` is no longer a wrapper around an encoded body, but instead just a thin wrapper around what is effectively `Box<dyn Any>`. This lets us deserialize a structure in one format and re-serialize it in another.
 * The server, instead of operating on a single static `AddressSpace` instead consists of multiple `NodeManager`s which is far more powerful, though can be harder to use.
 * The server will no longer automatically read from values for monitored items. Instead, users need to `notify` the server about any changes.
 * We now support loading NodeSet2 files at runtime.
 * We have basic support for custom structures.
 * Numerous bugfixes and performance improvements.

# Different design philosophy

The original library explicitly aimed to support the OPC-UA embedded server/client profiles. This library, in general, is open to implementing _any_ part of the OPC-UA standard, so long as it can be done in a good way that meshes well with the rest of the library.

This does not mean that it currently implements the entire standard, just that in theory we are open for changes that lets us cover more things defined in the standard.

We will not include support for any companion standards, but we _are_ open for changes that make it easier to write extension libraries defining companion standards. We may even be open for publishing those libraries from here, just not as part of the main library.

On the other hand, our focus on implementing the standard as a whole may come at the cost of making it harder to use in embedded settings. Again, we are open for expanding on the library in ways that make it easier to use in embedded settings, so long as that does not affect the rest of the library adversely.
