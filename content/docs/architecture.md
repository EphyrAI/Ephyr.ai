---
title: "Architecture"
description: "Ephyr's three-process architecture and security model"
weight: 20
---

## Three Isolated Processes

```
┌──────────────┐                ┌──────────────────┐                ┌──────────────────┐
│              │   MCP :8554    │                  │   Unix socket  │                  │
│  AI Agent    ├───────────────▶│   ephyr-broker   ├───────────────▶│   ephyr-signer   │
│              │                │                  │                │                  │
└──────────────┘                └────────┬─────────┘                └──────────────────┘
                                         │
                          ┌──────────────┼──────────────┐
                          ▼              ▼              ▼
                    ┌──────────┐  ┌──────────┐  ┌──────────┐
                    │ SSH hosts│  │ HTTP APIs│  │ MCP      │
                    │          │  │          │  │ servers  │
                    └──────────┘  └──────────┘  └──────────┘
```

### ephyr-signer

Holds the Ed25519 CA private key. Listens exclusively on a Unix socket. Sandboxed via systemd (`ProtectSystem=strict`, `PrivateNetwork=true`, `NoNewPrivileges=true`). Never touches the network.

Its only job: sign SSH certificates and delegation certificates when asked by the broker.

### ephyr-broker

Handles everything else:

- **Policy evaluation** — loads YAML, evaluates access requests against per-agent rules
- **Task identity** — issues task tokens with capability envelopes, manages delegation chains
- **SSH certificates** — requests signing from ephyr-signer, delivers certs to agents
- **HTTP proxy** — injects stored credentials into outbound API requests
- **MCP federation** — aggregates tools from remote MCP servers
- **Audit logging** — structured JSON-line output with full correlation
- **Admin dashboard** — 11-view web UI on port 8553

### ephyr (CLI)

Agent-side tool for requesting certificates and running commands. Communicates with the broker over Unix socket or HTTP.

## Security Model

### What Ephyr Enforces

| Control | Mechanism |
|---------|-----------|
| Access issuance | Policy YAML, per-agent rules |
| Task scope | Capability envelopes, macaroon caveats |
| Credential isolation | Signer/broker process separation |
| Grant expiry | TTL on certificates, epoch watermarking |
| Delegation limits | Max depth, envelope intersection |
| Audit trail | JSON-line structured logging |
| Network isolation | nftables (agent UID blocked from backends) |

### What Ephyr Does Not Enforce

Ephyr is a broker, not a host agent. It controls *whether* access is granted and *what scope* it carries. It does not control what happens after access is granted.

- **Command filtering** — delegated to the host shell and sudoers
- **OS-level isolation** — SELinux, AppArmor, filesystem permissions
- **Bearer token binding** — coming in Ephyr Bind (v0.3)

### Hardening

- Unix socket authentication via `SO_PEERCRED`
- Constant-time token comparison
- Systemd sandboxing on both processes
- CA key never on the network
- Network isolation via nftables (agent UID cannot reach backend IPs directly)
- Epoch-based revocation without blocklists or CRLs

## Dependencies

Ephyr has a minimal dependency footprint:

| Module | Purpose |
|--------|---------|
| `github.com/gorilla/websocket` | WebSocket for dashboard terminal |
| `golang.org/x/crypto` | SSH certificates, bcrypt |
| `gopkg.in/yaml.v3` | Policy YAML parsing |
| `gopkg.in/macaroon.v2` | Macaroon token format (Delegation tier) |

No external databases. No message queues. No container runtime. No ORM.
