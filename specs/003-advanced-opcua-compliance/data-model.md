# Data Model

## Key Entities

### Security Group
- **Fields**: `group_id` (String), `current_key` (AesKey), `next_key` (AesKey), `key_lifetime` (Duration)
- **Relationships**: 1:N with Publishers, 1:N with Subscribers
- **Validation Rules**: `key_lifetime` > 0.

### Event Filter
- **Fields**: `select_clauses` (List<SimpleAttributeOperand>), `where_clause` (ContentFilter)
- **Relationships**: Attached to a Subscription.

### Encrypted Secret
- **Fields**: `algorithm` (String), `encrypted_data` (Vec<u8>)
- **Validation Rules**: Must decrypt using RSA-OAEP.

### Query Result
- **Fields**: `node_ids` (List<NodeId>), `attributes` (List<Variant>), `continuation_point` (Option<Vec<u8>>)
- **State Transitions**: `continuation_point` is consumed by `QueryNext`.
