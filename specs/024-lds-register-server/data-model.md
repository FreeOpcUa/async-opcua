# Data Model: RegisterServer / RegisterServer2 (LDS)

No persistence. New in-memory state on `ServerInfo`.

## Registry (NEW, on ServerInfo)
- `registered: RwLock<HashMap<UAString /*server_uri*/, RegisteredServer>>`, capped at
  `MAX_REGISTERED_SERVERS`.
- ops: apply a RegisterServer call (upsert if `is_online`, remove if not); list registered as
  `ApplicationDescription`s for FindServers.

## RegisteredServer (existing wire type) → ApplicationDescription mapping
- server_uri → application_uri (also the registry key)
- server_names (localized) → application_name (by requested locale / first)
- server_type → application_type
- gateway_server_uri → gateway_server_uri
- discovery_urls → discovery_urls
- product_uri → product_uri

## Requests/Responses (existing wire types)
- RegisterServerRequest { server: RegisteredServer } → RegisterServerResponse (status via header).
- RegisterServer2Request { server, discovery_configuration: Option<Vec<ExtensionObject>> } →
  RegisterServer2Response { configuration_results: Option<Vec<StatusCode>>, diagnostic_infos }.

## Behavioral states
- register(is_online=true) → registry upsert → FindServers includes it.
- register(is_online=false) → registry remove → FindServers excludes it.
- RegisterServer2 mdns config element → configuration_results[i] = BadNotSupported; server still registered.
- registry at cap → new distinct registration rejected (status), no growth.
- FindServersOnNetwork → BadServiceUnsupported (unchanged).
