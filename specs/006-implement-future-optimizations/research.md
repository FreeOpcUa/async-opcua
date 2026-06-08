# Architectural Research: Future Performance Optimizations

This document records the design decisions, trade-offs, and alternatives evaluated during the research phase of the performance optimization implementation.

---

## 1. O(1) Session Lookup Registry

### Decision
Use a concurrent `DashMap` (sharded concurrent hash map) in `SessionManager` to register and route token-based lookups directly to session actors using their authentication token (`NodeId`) as the key.

### Rationale
*   **Constant Time Performance**: Replaces a linear `find` iteration over all active sessions (which is **O(N)**) with an **O(1)** hash table lookup. Under high session concurrency (up to 20,000 active sessions), this completely eliminates the CPU bottleneck on request authentication.
*   **Fine-Grained Concurrency**: `DashMap` shards the internal storage, allowing concurrent reads and writes to different sessions without acquiring a global lock.

### Alternatives Considered
*   **Global `RwLock<HashMap>`**: Acquires a read lock on the entire hash map during lookups. This causes massive thread contention and stalls when thousands of clients send requests concurrently.
*   **Linear Search Scan (Status Quo)**: Kept request lookup at O(N) complexity, requiring serial read locks on every session sequentially, which is highly inefficient.

---

## 2. Zero-Copy Outbound Serialization

### Decision
Implement direct serialization traits writing directly into a connection-local, reusable `BytesMut` buffer. Reset the buffer cursor (without deallocating) after each write to the network stream.

### Rationale
*   **Zero Allocations**: Dedicating one reusable `BytesMut` per connection write loop (which processes writes sequentially) avoids allocating temporary byte vectors (`Vec<u8>`) during message framing.
*   **Memory Stability**: Reusing connection-local memory buffers prevents heap fragmentation and memory page allocation churn on the hot transmit path.

### Alternatives Considered
*   **Global Lock-Free Buffer Pool**: Borrows and returns buffers from a centralized pool. While memory-efficient, it introduces cross-thread synchronization overhead and potential lock contention.
*   **On-Demand Allocation**: Allocates a new `BytesMut` buffer on every message. This is simpler to implement but violates the zero-allocation requirement and increases GC/deallocation overhead.

---

## 3. Actor-Based Session State

### Decision
Isolate the mutable `Session` state inside a thread-safe actor that executes inside a dedicated async task, processing incoming requests sequentially from an `mpsc` queue.

### Rationale
*   **Lock-Free State**: Eliminates `Arc<RwLock<Session>>` contention. Multiple concurrent client operations (e.g., publish loops, attribute reads, status checks) submit message tasks to the actor instead of competing for lock access.
*   **Deadlock Prevention**: By removing nested locks on session objects, deadlocks between the session manager and individual sessions are completely avoided.

### Alternatives Considered
*   **Fine-Grained Mutexes**: Locking individual fields of the `Session` struct. This increases code complexity significantly and increases the risk of deadlocks when operations access multiple fields.
*   **Global Read/Write Locks (Status Quo)**: Multiple async tasks serialize themselves on the session lock, causing performance degradation under load.

---

## 4. Notification Allocation Pooling in Subscriptions

### Decision
Pool subscription notification objects using `lockfree_object_pool::LinearObjectPool`. Under pool exhaustion (extreme value update bursts), the publishing thread will block and wait for structures to be recycled.

### Rationale
*   **Predictable Memory footprint**: Reusing pre-allocated notification structures reduces the GC overhead and memory fragmentation caused by high-frequency telemetry updates (50k items at 10Hz).
*   **Strict Memory Bounding**: Enforcing block/wait behavior on pool exhaustion guarantees that memory consumption has a hard, predictable ceiling, preventing out-of-memory crashes during peak bursts.

### Alternatives Considered
*   **Dynamic Unbounded Pool Growth**: Allocates new memory on demand during bursts and keeps them in the pool. This risks unbound memory growth if a permanent peak occurs.
*   **Message Discarding**: Discards telemetry frames if the pool is full. This is unacceptable for industrial SCADA applications where data consistency and loss prevention are mandatory.
