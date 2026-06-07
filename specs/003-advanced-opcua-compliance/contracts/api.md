# Interface Contracts

## Server API

- `GetSecurityKeys`: Receives group ID, returns current and future security keys for PubSub.
- `QueryFirst`: Receives `NodeTypeDescription`, `ContentFilter`, returns matched nodes and `continuation_point`.
- `QueryNext`: Receives `continuation_point`, returns next batch of nodes.
- `ActivateSession`: Extended to accept `EncryptedSecret` and handles tarpitting on failure.
