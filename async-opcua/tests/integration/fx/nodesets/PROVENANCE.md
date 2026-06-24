# Vendored OPC UA FX nodesets

- **Source:** https://github.com/OPCFoundation/UA-Nodeset (branch `latest`)
- **Commit:** `c335f575ca77c025cdf5dc994b03411d093571ef`
- **Files:**
  - `Opc.Ua.Di.NodeSet2.xml` (from `DI/`) — Device Integration, required by the FX nodesets
  - `opc.ua.fx.data.nodeset2.xml` (from `UAFX/`) — OPC UA FX data structures
  - `opc.ua.fx.ac.nodeset2.xml` (from `UAFX/`) — OPC UA FX AutomationComponent model
  - `opc.ua.fx.cm.nodeset2.xml` (from `UAFX/`) — OPC UA FX Connection Management
- **License:** OPC Foundation MIT License 1.00 (http://opcfoundation.org/License/MIT/1.00/)

Used by the FX spike test (`async-opcua/tests/integration/fx_spike.rs`) to load the FX information
model at runtime. Dependency order: Core → DI → FX/Data → FX/AC → FX/CM.
