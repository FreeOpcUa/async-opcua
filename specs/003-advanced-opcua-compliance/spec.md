# Feature Specification: Advanced OPC UA Compliance

**Feature Branch**: `003-advanced-opcua-compliance`  
**Created**: 2026-06-07  
**Status**: Draft  
**Input**: User description: "continue using the plan in local/ to implement the full OPC-UA spec"

## Clarifications

### Session 2026-06-07
- Q: For the Graph Query Service (`QueryFirst`), should we support complex relationship joining (following references), or only basic node type and property filtering? → A: Complex joining (follow references to filter by related nodes)
- Q: How should PubSub security keys be actively rotated (triggered) during live message transmission? → A: Time-based rotation (keys expire and rotate after a fixed time duration)
- Q: How should the server handle repeated failed session activations with invalid `EncryptedSecret`s (authentication failures)? → A: Return a delayed BadUserAccessDenied response (tarpitting) to slow down brute force

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Secure PubSub Message Exchange (Priority: P1)

An enterprise security officer needs PubSub NetworkMessages to be cryptographically signed and encrypted using keys retrieved from a key distribution service, so telemetry cannot be intercepted or tampered with on the broker or network.

**Why this priority**: Industrial telemetry over shared brokers (MQTT/AMQP) or open networks must be secured to prevent snooping or spoofing of plant floor actions.

**Independent Test**: Configure a dataset publisher to sign and encrypt UADP messages, run a subscriber without keys to confirm it cannot decrypt the payload, and then run a subscriber with valid distributed keys to confirm successful verification and decryption.

**Acceptance Scenarios**:

1. **Given** a PubSub connection is configured with MessageSecurityMode::SignAndEncrypt, **When** variables change and messages are published, **Then** payloads are signed and encrypted using group keys, and unsigned/unencrypted messages are rejected by subscribers.
2. **Given** a publisher requesting security keys, **When** it queries the key distribution service (GetSecurityKeys), **Then** it receives the current security keys and key lifetimes.

---

### User Story 2 - Subscription Event Filtering (Priority: P1)

An operator needs to subscribe to specific machine events and filter out irrelevant notifications (e.g. only receive alarms of severity > 500, or only select specific event fields like Severity and Message), saving network bandwidth.

**Why this priority**: Factory-floor networks can be flooded with minor events; filtering ensures operators only receive critical, actionable events.

**Independent Test**: Create alarm events of varying severities, configure a subscription with an EventFilter containing SelectClauses and WhereClauses, and verify that the client only receives events matching the filter with the requested fields.

**Acceptance Scenarios**:

1. **Given** a client creates an event subscription with an EventFilter, **When** events of low severity (< 500) are generated, **Then** no notifications are sent to the client.
2. **Given** a client event subscription, **When** events of high severity (>= 500) are generated, **Then** notifications containing only the selected fields are sent to the client.

---

### User Story 3 - Asymmetric Encrypted Secrets (Priority: P1)

An administrator needs client user credentials (passwords, tokens) to be encrypted using the server's public key (using standard OPC-UA EncryptedSecret) rather than legacy cleartext or deprecated security algorithms.

**Why this priority**: Storing or transmitting user passwords in cleartext or weak legacy encryption is a major compliance violation.

**Independent Test**: Connect a client using standard EncryptedSecret, and verify that the server decrypts the user credentials using its private key and activates the session securely.

**Acceptance Scenarios**:

1. **Given** a server supporting standard modern security policies, **When** a client sends an ActivateSessionRequest with user credentials wrapped in an EncryptedSecret (using RSA-OAEP), **Then** the server successfully decrypts and validates the credentials.

---

### User Story 4 - Graph Query Service (Priority: P2)

A client application needs to search the server's complex object graph using the standard QueryFirst/QueryNext services to find nodes matching specific criteria (e.g. all objects of a certain type with specific properties), without browsing the entire address space node by node.

**Why this priority**: Navigating large vendor models with millions of nodes via iterative Browse calls is highly inefficient and resource-intensive.

**Independent Test**: Execute a QueryFirst call with a query filter on the address space, and verify the server returns the matching NodeIds and attributes.

**Acceptance Scenarios**:

1. **Given** a large address space, **When** a client calls QueryFirst with a type filter and criteria, **Then** the server returns the matching nodes and their attributes, along with a query continuation point if results exceed limits.

---

### Edge Cases

- **Key Rotation in PubSub**: PubSub security keys are rotated based on fixed time durations. When they expire mid-transmission, publishers and subscribers must seamlessly transition to the new key without losing messages.
- **Malformed Event Filters**: If a client sends an EventFilter with invalid SelectClauses or unsupported operators in the WhereClause, the server must reject it with a status code of BadFilterNotSupported.
- **Decryption Failures**: If user credentials decrypt to malformed data or fail validation, the server must return a delayed `BadUserAccessDenied` response (tarpitting) to slow down potential brute-force attacks.
- **Large Query Results**: If a query returns millions of nodes, the server must enforce paging limits and use query continuation points to prevent memory exhaustion.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST support the `GetSecurityKeys` service to distribute cryptographic keys to PubSub groups.
- **FR-002**: System MUST support UADP datagram signing and encryption using standard algorithms (AES-128-CBC, AES-256-CBC, HMAC-SHA256).
- **FR-003**: System MUST support client-specified EventFilters in subscriptions, including SelectClauses and WhereClauses with standard logical operators (AND, OR, NOT, GREATER_THAN, EQUALS).
- **FR-004**: System MUST support standard `EncryptedSecret` decryption (using RSA-OAEP) for user identity tokens.
- **FR-005**: System MUST support the `QueryFirst` and `QueryNext` services to allow clients to query nodes using filters and criteria, including complex relationship joining (following references to filter by related nodes).
- **FR-006**: System MUST enforce authorization checks on all query results and event fields, filtering out nodes the user is not permitted to see.

### Key Entities *(include if feature involves data)*

- **Security Group**: Represents a logical grouping of PubSub publishers and subscribers sharing common cryptographic keys.
- **Event Filter**: A structure containing SelectClauses (fields to return) and a WhereClause (logical criteria to match).
- **Encrypted Secret**: A byte string containing client credentials encrypted with the server's public key.
- **Query Result**: A collection of matching node descriptions and attributes returned by the Query service.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Encrypted PubSub UADP messages cannot be decrypted by standard packet sniffers without the group keys.
- **SC-002**: Subscriptions utilizing EventFilters show a network traffic reduction of at least 80% compared to unfiltered subscriptions.
- **SC-003**: Encrypted user credentials are successfully decrypted and authenticated in under 50ms during session activation.
- **SC-004**: Graph queries return the first page of results in under 100ms for address spaces with up to 100k nodes.

## Assumptions

- **Cryptography Library**: We assume the existing `async-opcua-crypto` crate is sufficient to perform RSA-OAEP decryption and AES-CBC symmetric encryption.
- **Group Key Server**: The key server is assumed to be local and integrated directly into the OPC UA server for this phase.
- **Query Service Fallback**: Custom node managers that do not implement the Query interface will return empty results without crashing the query request.
