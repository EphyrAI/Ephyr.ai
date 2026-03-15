---
title: "Architecture"
description: "Ephyr's three-process architecture and security model"
weight: 20
---

## Process Isolation

```
Agent (MCP client)
    │
    │ Bearer: mac_<base64url macaroon>
    │
    ▼
┌──────────────────┐           ┌──────────────────┐
│  ephyr-broker    │  IPC      │  ephyr-signer    │
│                  ├──────────►│                  │
│  Policy engine   │           │  CA key custody  │
│  Macaroon verify │           │  SSH cert signing│
│  HMAC reducer    │           │  Never on network│
│  Audit logger    │           └──────────────────┘
│  HTTP proxy      │
│  MCP federation  │
│  Task identity   │
└────┬───────┬─────┘
     │       │
  SSH certs  HTTP proxy    MCP federation
     │       │                  │
     ▼       ▼                  ▼
  Targets  Services       Remote MCP servers
```

### ephyr-signer

Holds the Ed25519 CA private key. Unix socket IPC. Systemd sandbox with `ProtectSystem=strict`, `MemoryDenyWriteExecute`, zero capabilities. Never touches the network.

Its jobs: sign SSH certificates and issue delegation certificates to the broker.

### ephyr-broker

Handles everything else:

- **HMAC chain verification** -- validates macaroon caveat chains
- **Effective envelope reducer** -- derives most-restrictive authority from accumulated caveats
- **Policy evaluation** -- eight-step pipeline with per-agent RBAC
- **SSH certificates** -- requests signing from signer via IPC
- **HTTP proxy** -- injects stored credentials into outbound requests
- **MCP federation** -- aggregates tools from remote MCP servers
- **Task tree management** -- ULID lineage, delegation chains, watermarks
- **Audit logging** -- structured JSON-line output with ULID correlation
- **Admin dashboard** -- 11-view web UI on port 8553

### ephyr (CLI)

Agent-side tool for direct operations. Includes `ephyr inspect` for examining macaroon caveats.

## Trust Model

### Tiered Trust

The signer is the root of trust. The broker generates ephemeral Ed25519 keypairs locally, sends only the public key to the signer, and receives a delegation certificate. Private key material never transits IPC.

Delegation certificates expire on a short cycle (default 1 hour). Broker compromise is bounded by delegation expiry. The root key never leaves the signer.

### Authentication Layers

| Layer | Mechanism | Strength |
|-------|-----------|----------|
| Unix socket | `SO_PEERCRED` (kernel-verified UID) | Unforgeable |
| Session tokens | 256-bit random via `crypto/rand` | Strong |
| Dashboard | Constant-time comparison (`crypto/subtle`) | Strong |
| MCP API keys | bcrypt-hashed, cost 10 | Strong |
| SSH certificates | Ed25519 chain of trust | Strong |
| Auth cache | SHA-256 keyed bcrypt result cache, configurable TTL | Performance |

### Adversary Tiers

1. **Unprivileged local user** -- can reach broker socket if in `ephyr-agents` group, but cannot impersonate another UID (SO_PEERCRED is kernel-enforced)
2. **Compromised agent** -- valid session, can request certs within policy limits, cannot exceed rate limits, role boundaries, or caps
3. **Network attacker** -- can reach TCP ports 8553/8554 but requires dashboard token or valid bcrypt API key

## Security Boundaries

### What Ephyr enforces

| Control | Mechanism |
|---------|-----------|
| Access issuance | Policy YAML, RBAC, eight-step pipeline |
| Task scope | Capability envelopes, macaroon caveats, HMAC chain |
| Credential isolation | Signer/broker process separation |
| Grant expiry | TTL on certificates, epoch watermarking |
| Delegation limits | Max depth 5, envelope intersection, TTL constraint |
| Audit trail | JSON-line structured logging with ULID correlation |
| Network isolation | nftables UID-based rules, CIDR allow/deny |

### What Ephyr does NOT enforce

- **Command filtering** -- the target host (shell restrictions, sudoers, filesystem permissions) is the enforcement layer
- **OS-level isolation** -- SELinux, AppArmor, filesystem permissions are outside scope
- **Push revocation to hosts** -- OpenSSH doesn't support online CRL for user certificates; TTL is the mitigation
- **Holder binding** -- task tokens are bearer tokens until Ephyr Bind ships
- **Multi-tenant isolation** -- single policy file, single CA; deploy separate instances for tenant boundaries

### Threat Model

14 enumerated threats with explicit mitigations. Key properties:

- Broker compromise does not expose the CA key
- Host compromise can abuse active grants within TTL only (default 5 minutes)
- Network isolation is defense-in-depth, not a substitute for host hardening

See the [Security Whitepaper](/whitepapers/security/) and [Threat Model](https://github.com/EphyrAI/Ephyr/blob/main/docs/THREAT_MODEL.md) for full details.

## Dependencies

Three direct dependencies, all well-established:

| Module | Purpose |
|--------|---------|
| `github.com/gorilla/websocket` | WebSocket for dashboard and terminal |
| `golang.org/x/crypto` | SSH certificates, bcrypt |
| `gopkg.in/yaml.v3` | Policy YAML parsing |

The macaroon implementation is pure Go stdlib (HMAC-SHA256 from `crypto/hmac`). No external macaroon dependency.

No external databases. No message queues. No container runtime. No ORM.
