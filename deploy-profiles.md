# async-opcua deployment profiles

Three tuned starting points. Each `limits:` block is a **drop-in replacement** for the
`limits:` section of `samples/server.conf`. Values are derived from `config/limits.rs`
defaults; only change what your workload needs. Pair with the build/runtime notes per tier.

Severity note: the one default worth fixing in **every** tier is
`max_notifications_per_publish: 0` (0 = unlimited → an unbounded publish response in RAM).

---

## 1. `micro` — Pi Zero W class (≤512 MB, 1–2 PLCs, isolated OT network)

Build: `cargo build --profile embedded --no-default-features --features server,ecc`
(turning off the default `aws-lc-rs` selects the C-toolchain-free pure-Rust `rsa` path — a fit for
this tier's isolated `SecurityPolicy::None` endpoint; see `docs/EMBEDDED_AUDIT_2026-06-18.md` §4.2.
Keep the default `aws-lc-rs` for secured endpoints — its RSA decrypt is constant-time).
Runtime: `#[tokio::main(flavor = "current_thread")]`; system allocator (no jemalloc/mimalloc).
Security: on a physically-isolated segment, expose only a `security_policy: None` endpoint to avoid
the RSA-handshake CPU spiral on the ARMv6 core. Otherwise raise client handshake timeouts.

```yaml
limits:
  max_array_length: 8192
  max_string_length: 16384
  max_byte_string_length: 16384
  max_message_size: 65536
  max_chunk_count: 4
  send_buffer_size: 8192
  receive_buffer_size: 8192
  max_browse_continuation_points: 16
  max_history_continuation_points: 4
  max_query_continuation_points: 4
  max_sessions: 4
  max_inflight_requests_per_connection: 32
  max_unactivated_sessions_per_channel: 2
  unactivated_session_timeout_ms: 5000
  subscriptions:
    max_subscriptions_per_session: 8
    max_pending_publish_requests: 4
    max_publish_requests_per_subscription: 2
    min_sampling_interval_ms: 500
    min_publishing_interval_ms: 500
    max_keep_alive_count: 30000
    default_keep_alive_count: 10
    max_monitored_items_per_sub: 100
    max_monitored_item_queue_size: 5
    max_lifetime_count: 90000
    max_notifications_per_publish: 100
    max_queued_notifications: 10
  operational:
    max_nodes_per_translate_browse_paths_to_node_ids: 50
    max_nodes_per_read: 256
    max_nodes_per_write: 256
    max_nodes_per_method_call: 32
    max_nodes_per_browse: 128
    max_nodes_per_register_nodes: 128
    max_monitored_items_per_call: 128
    max_nodes_per_history_read_data: 50
    max_nodes_per_history_read_events: 50
    max_nodes_per_history_update: 50
    max_references_per_browse_node: 256
    max_node_descs_per_query: 50
    max_data_sets_query_return: 128
    max_references_query_return: 50
    max_nodes_per_node_management: 128
    max_references_per_references_management: 128
    max_subscriptions_per_call: 8
```

---

## 2. `gateway` — embedded Linux gateway (Pi 4 / Zero 2 W, ~1 GB, handful of clients, security ON)

Build: `cargo build --profile embedded` (keep security features). Runtime: multi-thread tokio is fine
(Zero 2 W / Pi 4 are multi-core). Security: enable a `Basic256Sha256` (Sign / SignAndEncrypt) endpoint;
expect a one-time RSA cost at connect.

```yaml
limits:
  max_array_length: 65535
  max_string_length: 65535
  max_byte_string_length: 65535
  max_message_size: 131072
  max_chunk_count: 5
  send_buffer_size: 32768
  receive_buffer_size: 32768
  max_browse_continuation_points: 256
  max_history_continuation_points: 64
  max_query_continuation_points: 64
  max_sessions: 8
  max_inflight_requests_per_connection: 128
  max_unactivated_sessions_per_channel: 4
  unactivated_session_timeout_ms: 10000
  subscriptions:
    max_subscriptions_per_session: 32
    max_pending_publish_requests: 10
    max_publish_requests_per_subscription: 4
    min_sampling_interval_ms: 250
    min_publishing_interval_ms: 250
    max_keep_alive_count: 30000
    default_keep_alive_count: 10
    max_monitored_items_per_sub: 2000
    max_monitored_item_queue_size: 10
    max_lifetime_count: 90000
    max_notifications_per_publish: 200
    max_queued_notifications: 20
  operational:
    max_nodes_per_translate_browse_paths_to_node_ids: 100
    max_nodes_per_read: 4096
    max_nodes_per_write: 4096
    max_nodes_per_method_call: 100
    max_nodes_per_browse: 1000
    max_nodes_per_register_nodes: 1000
    max_monitored_items_per_call: 512
    max_nodes_per_history_read_data: 100
    max_nodes_per_history_read_events: 100
    max_nodes_per_history_update: 100
    max_references_per_browse_node: 1000
    max_node_descs_per_query: 100
    max_data_sets_query_return: 1000
    max_references_query_return: 100
    max_nodes_per_node_management: 1000
    max_references_per_references_management: 1000
    max_subscriptions_per_call: 10
```

---

## 3. `server` — standard / enterprise (full resources, security required, many clients)

This is the shipped default, with the one fix: bound `max_notifications_per_publish`.
Build: default release. Runtime: multi-thread tokio.

```yaml
# Same as samples/server.conf defaults, EXCEPT:
limits:
  subscriptions:
    max_notifications_per_publish: 1000   # was 0 (= unlimited); bound the publish response
  # (everything else: keep server.conf defaults)
```

> Footgun guard for all tiers: never set BOTH `max_chunk_count: 0` and `max_message_size: 0`
> (that resolves to "unlimited" → unbounded chunk buffering). Keep at least one non-zero.
