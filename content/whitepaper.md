---
title: "Ephyr Architecture"
description: "Ephemeral infrastructure access for AI agents — Architecture specification"
layout: "simple"
---

<div class="whitepaper-header">
<p class="wp-meta"><strong>Status:</strong> Architecture specification &nbsp;|&nbsp; <strong>Author:</strong> Ben Spanswick &nbsp;|&nbsp; <strong>Date:</strong> March 2026</p>
<p class="wp-meta"><strong>Reference:</strong> DeepMind "Intelligent AI Delegation" (arXiv:2602.11865, Feb 2026)</p>
</div>

## What Ephyr Is

Ephyr is an access broker for AI agents. It sits between agent runtimes and infrastructure, issuing ephemeral credentials, enforcing policy, and auditing every action. Agents never hold long-lived secrets. A single MCP connection replaces SSH keys, API tokens, and service credentials with one unified, policy-governed interface.

Ephyr evolves through three capability tiers. Each tier adds a layer of security and control. All tiers share the same broker, the same audit pipeline, and the same deployment model.

| Tier | Name | What it adds |
|---|---|---|
| 1 | **Ephyr Core** | Brokered access, ephemeral credentials, policy, audit |
| 2 | **Ephyr Delegation** | Macaroon-based delegated task authority with cryptographic attenuation |
| 3 | **Ephyr Bind** | Holder-bound tokens, proof-of-possession, replay resistance |

Each tier is a strict superset of the previous. Ephyr Delegation includes everything in Core. Ephyr Bind includes everything in Delegation.

---

# Tier 1: Ephyr Core

*The foundational broker for task-scoped, policy-controlled access.*

## Architecture

Ephyr runs as three isolated processes with strict privilege separation:

```
+------------------+  Unix socket  +------------------+  Unix socket  +------------------+
|   Agent (CLI)    +-------------->|   ephyr-broker   +-------------->|   ephyr-signer   |
+------------------+               |                  |               |  CA key holder   |
                                   |  Policy engine   |               |  Signs certs     |
+------------------+  HTTP :8554   |  Session manager |               |  Never on network|
|   Agent (MCP)    +-------------->|  Audit logger    |               +------------------+
|  Claude, etc.    |               |  MCP server      |
+------------------+               |  HTTP proxy      |
                                   |  MCP federation  |
                                   +------------------+
```

**ephyr-signer** holds the Ed25519 CA private key and does nothing else. Unix socket IPC, systemd sandbox, zero capabilities.

**ephyr-broker** loads policy, evaluates requests, manages sessions, serves the MCP endpoint, proxies HTTP with credential injection, federates remote MCP servers, and writes structured audit logs.

**ephyr** (CLI) is the agent-side tool for direct operations from the broker host.

## Tiered Trust

The signer is the root of trust but is never on the hot path.

**Key custody inversion:** The broker generates its own ephemeral Ed25519 keypair locally. It sends only the public key to the signer (CSR-equivalent). The signer signs the public key and returns a delegation cert. Private key material never transits IPC.

```
Broker                         Signer
  │                              │
  ├── generate keypair locally   │
  ├── send public key ──────────>│
  │                              ├── sign with root key
  │<── delegation cert ──────────┤
  │    (no private key)          │
  ├── store cert + local key     │
  │    ... rotate before expiry  │
```

The delegation cert expires on a short cycle (default 1 hour). Broker compromise is bounded by delegation expiry. The root key never leaves the signer.

## Task Identity

The unit of identity is the **task run** — not the long-lived agent service, not an individual model call, not the human operator. A task run is a bounded unit of work: "deploy v2.3 to staging," "investigate high CPU on webserver," "run nightly backup validation."

Every task receives a ULID (lexicographically sortable, collision-resistant, encodes creation time). Every brokered action is correlated to a task ID in the audit log.

### Identity URN scheme

The `initiated_by` claim uses a structured identifier format designed for future federation without schema changes:

`clauth:<provider-class>:<provider-specific-identifier>`

| Context | Example |
|---|---|
| Local UID | `clauth:local:uid:1000` |
| API key | `clauth:apikey:ak_7f3b2a` |
| Future OIDC | `clauth:oidc:google.com:sub:987654321` |
| Future SPIFFE | `clauth:spiffe:trust.example.com:ns/default/sa/claude` |

Trust strength varies by bootstrap method. `clauth:local:uid:1000` is kernel-anchored via `SO_PEERCRED` (strong). `clauth:apikey:*` is bearer-token-based (weaker). Policy rules should account for this.

## Revocation: Epoch Watermarking

Instead of tracking individual token IDs in a blocklist, Ephyr uses epoch watermarking. The broker maintains a map of revoked task IDs with timestamps. Any token issued before the watermark is dead.

```go
// Revocation event
watermarks["01HQX7K9..."] = time.Now()

// Validation (on every request)
for each task_id in lineage:
    if watermarks[task_id] exists AND token.iat < watermarks[task_id]:
        → REJECT
```

Revoking a parent instantly invalidates all children. Watermarks self-clean when max task TTL passes. No per-token blocklists, no garbage collection edge cases.

## Policy Engine

Declarative YAML with hot-reload via SIGHUP. Eight-step evaluation pipeline for every request: agent exists, target exists, role allowed, duration clamped, concurrent limits, duplicate handling, global limits, approval mode. Every denial includes a specific reason.

## What Ships in Ephyr Core

| Version | Deliverable |
|---|---|
| v0.1 | Broker foundation: SSH/HTTP/MCP brokered access, policy, audit, ephemeral SSH certificates |
| v0.2a | Task-scoped identity: tiered trust, JWT-based task tokens on SSH exec path, epoch watermarking, ULID task IDs, identity URN scheme |
| v0.2a.1 | CTT-E validation extended to HTTP proxy and MCP federation paths |

---

# Tier 2: Ephyr Delegation

*Delegated, attenuated task authority for multi-agent workflows.*

Ephyr Delegation builds on Core by replacing JWT-based task tokens with macaroon-based tokens and adding a delegation engine with cryptographic attenuation.

## Why Macaroons

DeepMind's "Intelligent AI Delegation" (February 2026) identified that MCP lacks a permission propagation layer for deep delegation chains and proposed Delegation Capability Tokens based on macaroons as the solution. Ephyr Delegation implements that architecture.

Macaroons are bearer credentials with chained HMAC caveats. Each caveat is an additional constraint. The HMAC chain makes caveat removal cryptographically impossible. But macaroons prove caveat *accumulation*, not semantic *attenuation* — that requires a deterministic reducer.

> Macaroons cryptographically prove monotonic caveat accumulation. The effective envelope reducer, applied at verification time, derives the most-restrictive interpretation of all accumulated caveats. Together, they guarantee that delegated authority can only narrow.

The HMAC chain prevents tampering. The reducer prevents misinterpretation. Both are required.

## Design Principle: Centralized Audit, Cryptographic Attenuation

All delegation flows through the broker. No offline delegation. The broker mediates every delegation event for ULID assignment, lineage tracking, pre-validation, and audit. But the broker uses macaroon HMAC chains — not ad-hoc set-intersection logic — to make caveat removal cryptographically impossible.

The broker is always in the loop. The math proves no caveats were stripped. The reducer proves what authority remains.

## Caveat Schema

Caveats are only for constraints that benefit from cryptographic accumulation. Per-hop metadata (task ULIDs, parent links, descriptions) lives in broker state.

### Authorization constraints (in the macaroon)

| Caveat | Reduction rule |
|---|---|
| `expires_before = <RFC3339>` | Minimum (earliest) |
| `target IN [<csv>]` | Set intersection |
| `role IN [<csv>]` | Set intersection |
| `service IN [<csv>]` | Set intersection |
| `remote IN [<csv>]` | Set intersection |
| `method IN [<csv>]` | Set intersection |
| `can_delegate = <bool>` | AND (most restrictive) |
| `delegation_depth <= <int>` | Minimum |

`delegation_depth` is the single knob for delegation chain length. A root task minted with `delegation_depth <= 3` can delegate a child at `<= 2`, then `<= 1`, then terminal (`can_delegate = false`). One concept, one caveat, no drift.

### Informational metadata (in the macaroon, not used for authorization)

| Caveat | Extraction rule |
|---|---|
| `agent = <n>` | First value wins (provenance) |
| `initiated_by = <URN>` | First value wins (provenance) |

### Per-hop metadata (broker state only)

| Field | Storage |
|---|---|
| Task ULID | `TaskTree` map |
| Parent task ULID | `TaskTree` map |
| Root task ULID | Macaroon `Id()` |
| Presenting agent | `TaskTree` map (session-layer binding) |
| Delegation timestamp | `TaskTree` map |
| Description | `TaskTree` map |

## Root Key Management

One root key per task tree. The macaroon `Id()` is the root task ULID. All descendants verify against the same root key via the HMAC chain. The broker stores one 32-byte key per root task, generated with `crypto/rand`, garbage-collected when the tree's max TTL passes.

## Effective Envelope Reducer

The reducer is the safety-critical component. It takes the full list of caveats from a macaroon and produces two outputs:

**`EffectiveEnvelope`** — authorization constraints derived by intersection (sets), minimum (numerics), and AND (booleans). Used by `Authorize(req)`.

**`TokenMetadata`** — informational fields (agent, initiated_by). Used for audit, not authorization.

A child that appends `target IN [db,cache]` after the parent's `target IN [db]` gets `intersect([db], [db,cache]) = [db]`. The escalation attempt is neutralized by set math. Unknown caveats fail closed.

## Request-Type-Aware Authorization

Not every envelope dimension is relevant to every request type:

| Request type | Relevant dimensions |
|---|---|
| SSH exec | `target`, `role`, `expires_before` |
| HTTP proxy | `service`, `method`, `expires_before` |
| MCP federation | `remote`, `expires_before` |
| Delegation | `can_delegate`, `delegation_depth`, `expires_before` |

Empty effective set on a relevant dimension means deny. Irrelevant dimensions are ignored. `method` is mandatory for HTTP proxy, irrelevant for SSH exec.

## Cross-Agent Delegation

Cross-agent delegation is permitted. A parent task owned by `claude` can delegate to `investigator-bot`. The `agent` caveat records provenance (who started the tree). Agent identity binding is enforced at the broker session layer: the `TaskTree` entry controls who can present each token. Cross-agent delegation requires the child agent to exist in policy, and the child envelope is the intersection of parent ceiling and child agent's own policy permissions.

## Verification Pipeline

Every brokered request passes through this eight-step pipeline:

1. **Verify macaroon signature** against root task key (HMAC chain)
2. **Parse caveats** and reject unknown/malformed entries (fail closed)
3. **Reduce** all constraint caveats into effective envelope
4. **Resolve current task** from broker state via signature digest
5. **Check watermark revocation** against task lineage
6. **Bind presenter to task** via session-layer agent identity
7. **Authorize request** against relevant envelope dimensions
8. **Run policy pipeline** for final approval and audit logging

## What Ships in Ephyr Delegation

| Version | Deliverable |
|---|---|
| v0.2b.1 | `gopkg.in/macaroon.v2` integrated, `internal/macaroon/` package |
| v0.2b.2 | Reducer with all reduction rules, fuzz-tested |
| v0.2b.3 | `task_create` issues macaroons for all agents, `TaskTree` lineage store |
| v0.2b.4 | All brokered paths verify macaroons (replaces JWT verification) |
| v0.2b.5 | `task_delegate` with broker-mediated attenuation |
| v0.2b.6 | `ephyr inspect` CLI, signature-to-task resolution |
| v0.2b.7 | Demo A (task identity + revocation) and Demo B (delegation + attenuation) |
| v0.2c | Dashboard: task tree visualization, caveat chain inspector, watermark revocation display |

---

# Tier 3: Ephyr Bind

*Holder-bound presentation of delegated authority.*

Ephyr Core and Delegation use bearer tokens. A leaked macaroon can be replayed by any party until expiry or watermark revocation. Ephyr Bind closes this gap: each task has two artifacts — a macaroon that defines its delegated authority, and an ephemeral keypair that defines who may present that authority.

> Delegation transfers authority, not possession. Each child task receives narrowed authority, but proves possession with its own key.

## The Problem

Without holder binding:

1. Agent gets token
2. Token leaks from logs, memory, proxy, or another process
3. Attacker replays token
4. Broker accepts it (until TTL expires or watermark hits)

The damage window is bounded by TTL (default 5 min) and watermark revocation, but the token alone is sufficient for access.

## Design: Separate Authority from Possession

The macaroon is good at expressing *what authority is delegated.* It is not a replay-resistant holder-bound format. The original macaroon paper explicitly discusses requiring the bearer to prove possession of a private key — treating the proof as a separate artifact from the authority token. Ephyr Bind follows that model.

Macaroons carry what the task may do. Task-bound keypairs prove who may present that authority.

### Key binding in broker state

Following the established pattern (per-hop identity lives in broker state, not in macaroon caveats), the holder public key is stored in the `TaskTree`, not as a caveat:

```go
type TaskEntry struct {
    TaskID       string
    ParentTaskID string
    RootTaskID   string
    Agent        string
    HolderPubKey ed25519.PublicKey  // presenter must prove possession
    Description  string
    CreatedAt    time.Time
}
```

The macaroon layer is completely untouched. The reducer is untouched. Bind is a pure addition to the verification pipeline.

### Proof-of-possession at request time

Every brokered request includes a signed proof alongside the macaroon:

```json
{
  "task_id": "01HQX7K9M2N4P6R8T0V2W4Y6",
  "req_type": "ssh_exec",
  "resource": "staging-web",
  "method": "exec",
  "mac_digest": "<SHA-256-of-serialized-macaroon>",
  "nonce": "a1b2c3d4e5f6a7b8",
  "ts": "2026-03-15T14:32:01Z"
}
```

| Field | Purpose |
|---|---|
| `task_id` | Ties proof to broker-resolved task identity |
| `req_type` | Prevents cross-request-type replay |
| `resource` | Prevents cross-target replay |
| `method` | Prevents cross-method replay |
| `mac_digest` | Prevents proof from being replayed with a different token |
| `nonce` | Unique per request, broker rejects duplicates within replay window |
| `ts` | Broker rejects proofs outside ±30 second validity window |

### Replay prevention

Short-lived nonce cache scoped by task. Entries garbage-collected when TTL passes. On broker restart, the cache is lost — but so are all active macaroons and root keys, so replay is impossible anyway.

### Graceful upgrade

If a task's `TaskTree` entry has `HolderPubKey = nil`, the PoP step is skipped (bearer mode). If set, PoP is mandatory. Policy can enforce binding: `require_pop: true` per agent or target. Existing deployments upgrade incrementally.

---

# Security Model

## What Ephyr provides (all tiers)

- **Brokered access.** Agents connect to one endpoint. The broker handles credentials, policy, and proxying.
- **Ephemeral credentials.** SSH certificates, service grants, and task tokens are short-lived.
- **Structured audit.** Every action is logged with agent identity, target, task correlation, timestamp, and outcome.
- **Epoch watermark revocation.** Revoking a parent instantly invalidates all descendants.

## What each tier adds

| Tier | Security property |
|---|---|
| **Delegation** | Cryptographic caveat accumulation, deterministic semantic narrowing, lineage-aware audit |
| **Bind** | Holder binding, proof-of-possession, replay resistance, authority/possession separation |

## What Ephyr does NOT provide

- **Command-level enforcement.** Ephyr controls which targets/roles/services an agent can access. What the agent does once connected is enforced by the target host.
- **Multi-tenant isolation.** Ephyr is single-tenant. The broker operator is trusted.
- **External identity federation.** OIDC/SPIFFE interop is a future extension.

---

# Invariants

These are hard rules. Violations are bugs.

1. **Caveats only ever narrow the effective envelope.** The reducer uses intersection, minimum, and AND. No reduction rule can widen authority.
2. **Lineage metadata never affects authorization.**
3. **One task tree uses exactly one root key.**
4. **Unknown caveats fail closed.**
5. **Empty effective set on a relevant dimension denies authorization.**
6. **Irrelevant dimensions do not affect authorization.**
7. **Broker restart invalidates all active task tokens.** Deliberate availability tradeoff, acceptable for single-tenant.
8. **Agent binding is session-layer, not caveat-layer.**
9. **The broker mediates all delegation.** Invisible children are architecturally impossible.
10. **Holder binding is in broker state, not macaroon caveats.** *(Bind tier)*
11. **Delegation transfers authority, not possession.** *(Bind tier)*

---

# DeepMind Alignment

Ephyr implements the Delegation Capability Token architecture proposed in "Intelligent AI Delegation" (arXiv:2602.11865):

| DeepMind requirement | Ephyr implementation | Tier |
|---|---|---|
| Attenuated tokens with cryptographic caveats | Macaroon first-party caveats with HMAC chain | Delegation |
| Least-privilege enforcement | Wildcard resolution at issuance, effective envelope reducer | Delegation |
| Authority transfer with accountability | Broker-mediated delegation with ULID tracking and audit | Delegation |
| Verifiable delegation chains | HMAC chain proves accumulation; reducer proves narrowing | Delegation |
| Runtime monitoring | Epoch watermark revocation, dashboard, activity ring buffer | Core |
| Short TTLs | `expires_before` caveat, reducer takes minimum across hops | Core + Delegation |
| Holder binding | DPoP-style proof-of-possession with bound keypair | Bind |

---

*One product, three tiers, each a strict superset. Core gives you brokered access. Delegation gives you cryptographic attenuation. Bind separates authority from possession. The broker mediates everything. The math proves the constraints held. The keys prove who presented them. The audit proves what happened.*
