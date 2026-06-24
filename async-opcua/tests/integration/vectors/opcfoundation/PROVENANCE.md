# Vendored OPC Foundation address-space ground truth

- **Source repo:** https://github.com/OPCFoundation/UA-Nodeset (branch `latest`)
- **Commit:** `c335f575ca77c025cdf5dc994b03411d093571ef`
- **File:** `Schema/NodeIds.csv` — the canonical registry of every standard OPC UA NodeId in the core
  namespace (`http://opcfoundation.org/UA/`): `SymbolName,NumericId,NodeClass`, 14,770 entries.
- **License:** OPC Foundation MIT License 1.00 (http://opcfoundation.org/License/MIT/1.00/).

Used as ground truth by the conformance address-space oracle (`address_space_oracle.rs`) and reused by
later conformance phases. NB: this CSV tracks namespace version 1.05.07; our bundled nodeset is
1.05.04, so the oracle enforces correctness of exposed nodes (and a coverage floor) rather than
exact presence — see the test header.
