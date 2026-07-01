# Quickstart: Instance-Scoped Server State

## Two-instance isolation test pattern (the core proof)

Each relocated item gets a test that stands up two independent owners and proves no cross-instance
visibility. Because the owner is `ServerInfo`, tests build two `ServerInfo` (or two `SessionManager`,
or two servers) and exercise the same key on each.

```rust
// FOTA cleanup + localized-text: same NodeId, two ServerInfo -> isolated
let info_a = server_info();          // test helper
let info_b = server_info();
let node = NodeId::new(1, 5);        // SAME id on both

remember_localized_text_attribute_value(&info_a, &node, AttributeId::DisplayName, &lt("en", "A"));
// B has nothing for that node:
assert!(info_b.localized_text_variants.get(&(node.clone(), AttributeId::DisplayName)).is_none());

register_session_file(&info_a, node.clone(), /*…*/);
assert!(cleanup_session(&info_b, &node).is_empty());   // B unaffected
```

```rust
// session id + locale map: two SessionManager -> independent id space + locale state
let mgr_a = SessionManager::new(info_a.clone(), notify());
let mgr_b = SessionManager::new(info_b.clone(), notify());
// each allocates from its own next_session_id; setting locales on A is invisible to B
```

## Single-server no-regression

The existing server suite already covers single-server behavior; it must pass unchanged. The
locale-negotiation tests (P4-GEN-03) and FOTA cleanup tests are the direct behavioral guards.

## Verification matrix

```bash
cargo test -p async-opcua-server            # isolation tests + full suite (no single-server regression)
cargo build -p async-opcua                  # default features unchanged
cargo clippy --workspace --all-features --lib -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref
cargo clippy -p async-opcua-server --all-targets -- -D warnings
cargo fmt --all                             # verify-clean-codegen gate (run before pushing!)
```

Expected: two-instance state is isolated; single-server unchanged; lints clean; tree fmt-clean.
