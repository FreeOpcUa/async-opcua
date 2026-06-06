# Advanced usage of the server

For basic usage of the server see [server](./server.md). This document assumes that you have read that first.

The `SimpleNodeManager` and built in auth manager are fine for very simple servers, but this quickly breaks down if you need to do something more advanced. Most production grade OPC-UA servers will use the more advanced features of the server library.

## Locking

Rust OPC UA uses almost exclusively _synchronous_ locks. These should _never_ be held over an await point (there is a clippy lint for this).

To avoid this, good practice is using local blocks.

```rust
// Do stuff...
let thing = {
    let mut lock = my_lock.write();
    // Do stuff with lock, without any `await`.

    // Return the result of the operation.
    result
};
// Now we can await.
my_future().await
```

If you _must_ hold a lock over an await point, or if you need to hold the lock for a long time waiting for some external event (in which case there really should be an await point involved), then you should use async locks from `tokio`.

## AuthManager

Most servers will need to define some sort of proper authentication, likely with hashed passwords or the like. This can be implemented using the `AuthManager`. This type contains methods for authenticating users. These methods are async, so you can do things like call external services or look up users in a database.

These services may also be used to cache information for later, such as the `TypeTreeForUser` discussed below, since they are async and are always called when a client first connects.

## InMemoryNodeManager

The `SimpleNodeManager` used in the basic server samples only allows synchronously fetching updates, and it doesn't allow implementing features such as `HistoryRead`. If what you want is an address space stored _in memory_, but you need to be able to override other features, you should use the `InMemoryNodeManager`.

In order to use this, you need to create a type implementing `InMemoryNodeManagerImpl` like

```rust
struct MyNodeManagerImpl {
    namespace_index: u16,
    // Private fields you need here
}

pub struct MyNodeManagerImplBuilder;

impl InMemoryNodeManagerImplBuilder for MyNodeManagerImplBuilder {
    type Impl = MyNodeManagerImpl;

    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        // Get the namespace index by registering the namespace in the global
        // namespace map.
        let namespace_index = {
            let mut type_tree = context.type_tree.write();
            type_tree
                .namespaces_mut()
                .add_namespace("http://my.namespace.uri")
        };
        // Add the namespace to the address space first...
        address_space.add_namespace("http://my.namespace.uri", namespace_index);

        // Here you should call your code that populates the address space.
        // You can also do this later in `init` if you need it to be async.

        MyNodeManagerImpl::new(namespace_index)
    }
}

#[async_trait::async_trait]
impl InMemoryNodeManagerImpl for MyNodeManagerImpl {
    async fn init(&self, address_space: &mut AddressSpace, context: ServerContext) {
        // Do any kind of async one-time setup here.
    }

    fn name(&self) -> &str {
        "my-node-manager"
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            namespace_uri: "http://my.namespace.uri".to_owned(),
            // You need to generate a namespace index, typically in `build` above.
            namespace_index: self.namespace_index,
            ..Default::default()
        }]
    }

    // Other methods you will probably want are
    // `read_values`, `create_value_monitored_items`,
    // `set_monitoring_mode`, `modify_monitored_items`,
    // `delete_monitored_items`.
}
```

This does not need to concern itself with the details of implementing methods like `Read`, `Write`, `Call`, etc. Instead it fills in gaps by implementing `Read` for values, implementing `Call` for methods that have been verified to exist, and by sampling values.

For simple synchrnous sampling you can use the `SyncSampler` utility from the server library.

For an example of how to use the `InMemoryNodeManager`, have a look at the [`CoreNodeManager`](../async-opcua-server/src/node_manager/memory/core.rs), which implements a node manager for the core namespace, including method calls, different sources for data being Read, and more.

## NodeManager trait

The next step up when it comes to customizability is implemening the `NodeManager` trait directly. This lets you present a _dynamic_ set of nodes that are not stored in memory. This is required if you, for example, want to create an OPC-UA server that keeps its nodes in a local database.

```rust
pub struct MyNodeManager {
    namespace_index: u16,
    // Other private fields here.
}

pub struct MyNodeManagerBuilder;

impl NodeManagerBuilder for MyNodeManagerBuilder {
    fn build(self: Box<Self>, context: ServerContext) -> Arc<DynNodeManager> {
        // Get the namespace index by registering the namespace in the global
        // namespace map.
        let namespace_index = {
            let mut type_tree = context.type_tree.write();
            type_tree
                .namespaces_mut()
                .add_namespace("http://my.namespace.uri")
        };
        Arc::new(MyNodeManager::new(namespace_index))
    }
}

impl NodeManager for MyNodeManager {
    fn owns_node(&self, id: &NodeId) -> bool {
        // This method should return true if the given node ID is owned by this node manager.
        // Node managers _must_ be able to tell this easily, typically either based on
        // the namespace index, or on some pattern in the node ID.
        id.namespace == self.namespace_index
    }

    fn name(&self) -> &str {
        "my-node-manager"
    }

    async fn init(&self, type_tree: &mut DefaultTypeTree, context: ServerContext) {
        // One time setup goes here
    }

    fn namespaces_for_user(&self, context: &RequestContext) -> Vec<NamespaceMetadata> {
        // This method is allowed to return different namespaces based on different users.
        // Note that you still have to consider how this interacts with other node managers,
        // and ensure that namespace indexes are correct, complete, and unique.

        // Typically this returns a static set of namespaces except for the _last_
        // node manager, which can return a dynamic list.

        vec![NamespaceMetadata {
            namespace_uri: "http://my.namespace.uri".to_owned(),
            // You need to generate a namespace index, typically in `build` above.
            namespace_index: self.namespace_index,
            ..Default::default()
        }]
    }
}
```

A node manager with just this will _work_ but it won't actually be able to provide any data or really function at all. Attempts at accessing any of the nodes owned by this node manager will fail.

Typically you want to implement at least a few other methods:

 - `read` for fetching attribute values.
 - `browse` for fetching nodes.
 - `resolve_external_references`, this is only needed if you need to handle other node managers returning references to this one.
 - `translate_browse_paths_to_node_ids`, most node managers can implement this by just calling `impl_translate_browse_paths_using_browse`.
 - `create_monitored_items`, `modify_monitored_items`, `set_monitoring_mode`, and `delete_monitored_items`, if you want to support subscriptions on nodes in this node manager. In this case you will need to handle subscriptions for non-value nodes as well, if you want to support that. Note that if you always call `SubscriptionCache::notify_data_change` when something changes, you don't need to add any methods for managing monitored items.

For a real node manager that implements the `NodeManager` trait directly, see [`DiagnosticsNodeManager`](../async-opcua-server/src/node_manager/memory/diagnostics.rs).

### Read

The `read` service gets a list of `ReadNode` which contains reqests for reading attributes of nodes. You will need to get the correct value for each node, and call `node_to_read.set_result(DataValue::new(...))`, or call `node_to_read.set_error(status_code)`.

These are typically either stored in a database, or generated dynamically based on the data the NodeId maps to.

For example, if the user reads `AccessLevel`, but you know that all your variables have an unconditional access level of `1`, then a reasonable implementation of `read` might just do

 - Check if the node exists and is a variable.
 - Return a datavalue with `1`.

The datavalue needs a timestamp. The correct thing to do for something like `AccessLevel` is to track when the node was created, and use that timestamp. It's not completely inappropriate, for values that can change, to simply set the timestamp to the time the node was last updated in general, and not track update times for each individual attribute.

### Browse

The `browse` service gets a list of `BrowseNode` and must store reference descriptions in those according to the filter for each node.

Each node also sets a limit on the number of references to return. This limit must be respected. If you wish to return further nodes after reaching the limit, you should set a `ContinuationPoint` on the `BrowseNode`. When you do this, the server takes care of storing the `ContinuationPoint` in the session object, and resume by calling `browse` on your node manager again when the user calls `browse_next`.

As such, you should always call `take_continuation_point` on each node at the start of each browse run, to identify whether you need to resume browsing.

`BrowseNode` contains a convenient method `add`, which you can use to implement a simple form of continuation, where each `ContinuationPoint` simply contains the remaining references, after filtering.

Then, when browsing you just do

```rust
struct MyContinuationPoint {
    nodes: VecDeque<ReferenceDescription>,
}

if let AddReferenceResult::Full(c) = node_to_browse.add(type_tree, reference) {
    continuation_point.nodes.push_back(c);
}
```

On a resume, you can add nodes to the browse node from the continuation point like

```rust
while node_to_browse.remaining() > 0 {
    let Some(ref_desc) = continuation_point.nodes.pop_back() else {
        break;
    };
    // This just adds the node without applying any filtering.
    node_to_browse.add_unchecked(ref_desc);
}
```

### External references

Most node managers should also implement `resolve_external_references`. This method takes a list of `ExternalReferenceRequest`s, which are essentially just a browse `result_mask`, (which you are allowed to ignore), and a `NodeId`. Node managers should iterate over the external references, and if they exist, call `set` on the reference requests with a `ReferenceDescription` representing the node they ask for.

When browsing, node managers can call `BrowseNode::push_external_reference` to add a reference to another node manager. These are not subject to normal filtering or limits, and the server handles continuation for these if necessary.
