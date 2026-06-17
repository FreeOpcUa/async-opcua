# Contract — Configuration & Feature Flags

The full set of config and Cargo-feature surface introduced or changed by this feature. This is the
"contract" downstream operators and integrators rely on. Values are defaults; all are overridable.

## Server config (additions / changes)

```
# Ingress rate control (FR-003/004/005/006/008)
max_inflight_requests_per_connection : usize   = <safe default>   # C3 backpressure threshold
max_unactivated_sessions_per_channel : usize   = <small default>  # C4
unactivated_session_timeout          : Duration= <few seconds>    # C4
max_connections_per_ip               : usize   = <default>        # H3 / N10
accept_rate_limit                    : optional                   # N10 (optional)
max_timeout_ms                       : applied as CEILING         # H2 (semantics fix, not new field)
max_monitored_items_per_sub          : usize   = <non-zero>       # H4 (default change 0 -> non-zero)

# Socket tuning (FR-026)
tcp_nodelay                          : bool     = true            # N1
tcp_keepalive                        : { enabled=true, idle, interval, count }  # N3
so_sndbuf / so_rcvbuf                : optional                   # N4 (optional)
```

Validation: every limit rejects invalid values at `ServerConfig::validate()` time; the existing
`password_security_policy` panic path (L8) becomes a `Result`/default instead of `panic!`.

## Client config (additions / changes)

```
connect_timeout            : Duration = 5..10 s   # N2 (FR-011)
max_failed_keep_alive_count: u64      = 3         # N8 (FR-012; was 0 = disabled)
channel_lifetime           : u32 ms   = 600_000   # N9 (FR-013; was 60_000)
secure-channel renewal timeout : derived from channel_lifetime/config (was hardcoded 30s)  # M10
tcp_nodelay                : bool      = true      # N1 (FR-026)
tcp_keepalive              : { ... }               # N3
trust_server_certs         : bool      = false; warn! when true; removed from samples/docs  # M9 (FR-035)
expected server cert/thumbprint pin : optional API # M8 (FR-035)
```

## Cargo features

```
async-opcua-crypto:
  default = []                         # was ["legacy-crypto"]  (FR-019 / M12)
  legacy-crypto = [ ... ]              # opt-in; enabling logs a weak-posture warning

async-opcua-client:
  legacy-crypto = ["async-opcua-crypto/legacy-crypto"]   # new (FR-019)
  websocket     = ["dep:tokio-tungstenite", "dep:tokio-rustls", ...]  # new (FR-044 / R5)
  # crypto dependency now uses default-features = false

async-opcua-server:
  metrics-exporter = [ ... ]           # new, optional (FR-031 / R6)

async-opcua (umbrella):
  forwards legacy-crypto / websocket / metrics-exporter to sub-crates

async-opcua-pubsub:
  rumqttc upgraded to a rustls-0.23 release (or MQTT transport feature-gated off-by-default)  # FR-023 / D2
```

**Build matrix (SC-008 gate)** — all three MUST build warning-free and pass tests:
1. default features
2. `--all-features`
3. `--no-default-features` (legacy crypto excluded across all crates)

## deny.toml (FR-022 / P1)

```
[advisories]
db-urls = [RustSec]
yanked  = "deny"
# Explicit, justified exceptions (no upstream fix):
[[advisories.ignore]]   # RUSTSEC-2023-0071 rsa "Marvin" — mitigated by aws-lc-rs decrypt migration
                        # (R0.1); kept only until the rsa decrypt path is fully removed. Review date set.
[bans]    # one rustls major; no duplicate TLS stacks
[sources] # crates.io only
```
CI runs `cargo deny check advisories bans sources` on a `cargo-deny` version that parses CVSS 4.0.
