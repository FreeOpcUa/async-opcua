# Quickstart: Implement One StatusCode Test Task

1. Pick exactly one unchecked task from [tasks.md](./tasks.md).
2. Open the matrix row named by the task in [contracts/statuscode-test-matrix.md](./contracts/statuscode-test-matrix.md).
3. Read the cited OPC UA Part/section and the target implementation file.
4. Add exactly one test function with the exact task-provided name in the target file.
5. If the test fails because production behavior is wrong, make the smallest implementation change needed for that one test.
6. Run the focused cargo test command named in the task phase.
7. Run `cargo fmt --all`.
8. Do not add additional test functions in the same task.

Example focused commands:

```bash
cargo test -p async-opcua-core bad_nonce_invalid_status_is_exact
cargo test -p async-opcua-types json_int64_encodes_as_decimal_string
cargo test -p async-opcua-pubsub udp_subscriber_bind_conflict_returns_bad_communication_error
```

Completion criteria for one task:

- One new test function exists.
- The test asserts the exact StatusCode or happy-path result.
- The test cites the OPC UA reference in a short comment.
- The focused cargo test passes.
