# Phase 0: Research & Architecture Decisions

## Decision 1: AddressSpace Concurrency Strategy
*   **Decision**: Use `dashmap::DashMap` for the `AddressSpace` graph.
*   **Rationale**: The previous `parking_lot::RwLock` implementation blocked all reads during any write, killing throughput. `DashMap` provides fine-grained locking per shard, enabling massive concurrent read/write throughput required by SCADA environments (SC-001). Weakly consistent iterators are acceptable for bulk querying.
*   **Alternatives considered**: 
    *   `scc::HashMap`: Faster but requires strict async contexts.
    *   `std::sync::RwLock`: Same global bottleneck.

## Decision 2: Zero-Copy Serialization
*   **Decision**: Utilize `bytes::Bytes` and `bytes::BytesMut` across the entire TCP codec stack.
*   **Rationale**: Allocating new `Vec<u8>` arrays for every chunk is expensive. Slicing `Bytes` allows the TCP pipeline to share references to the same underlying memory buffer without `memcpy`, slashing CPU/Memory bloat (SC-002).
*   **Alternatives considered**: 
    *   Raw `&[u8]` lifetimes: Creates complex lifecycle issues in async contexts.

## Decision 3: Async-Aware LRU Cache
*   **Decision**: Implement `moka::future::Cache`.
*   **Rationale**: The current history continuation points cache uses an O(N) synchronous Mutex prune loop. `moka` is a high-performance, concurrent, async-aware cache that natively supports bounded capacity and automatic LRU eviction without blocking the Tokio executor (SC-005).
*   **Alternatives considered**:
    *   `lru` crate under `tokio::sync::Mutex`: Could introduce lock contention.

## Decision 4: Deterministic TSN Networking
*   **Decision**: Use Linux `AF_XDP` raw sockets (via `xsk-rs` or custom `libc` bindings) with a fallback to standard UDP sockets routed through Linux `tc taprio` qdiscs.
*   **Rationale**: `AF_XDP` provides kernel-bypass user-space packet injection, giving us absolute lowest latency and deterministic sub-millisecond jitter (SC-003). `tc taprio` ensures the fallback is still hardware-scheduled.
*   **Alternatives considered**:
    *   Standard `std::net::UdpSocket`: Insufficient for strict real-time deterministic latency.

## Decision 5: Functional Safety (Part 15) Target
*   **Decision**: Build the `SPDU` (Safety Protocol Data Unit) wrapper with strict IEC 61508 SIL 3 CRC signatures.
*   **Rationale**: Ensures any network delays, corruptions, or loss trigger a safe-state transition (SC-004). This requires wrapping standard payload data into specialized cryptographically verifiable structures.
*   **Alternatives considered**:
    *   SIL 2 target: Insufficient for heavy industrial robotics.
