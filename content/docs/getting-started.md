---
title: "Getting Started"
description: "Install and configure Ephyr"
weight: 30
---

## Requirements

- **Go 1.24+** -- uses enhanced routing patterns and recent stdlib features
- **Linux** -- `SO_PEERCRED` for Unix socket peer authentication is Linux-specific
- **systemd** -- optional but recommended for production
- **OpenSSH** -- target hosts need `TrustedUserCAKeys` configured
- **nftables** -- recommended for network isolation

## Quick Start with Docker (fastest)

```bash
git clone https://github.com/EphyrAI/Ephyr.git
cd Ephyr
./examples/generate-ca-key.sh
docker compose up --build -d
```

Dashboard at `http://localhost:8553` (token: `changeme`). Edit `examples/policy.yaml` to add your targets.

## Native Install with `ephyr init`

Ephyr ships as a single binary with all subcommands. Build it, then run the interactive setup wizard.

```bash
git clone https://github.com/EphyrAI/Ephyr.git
cd Ephyr && go build -o /usr/local/bin/ephyr ./cmd/ephyr
sudo ephyr init
```

`ephyr init` generates the CA key, writes an example policy, creates the system user and directories, installs systemd units, and starts both services. Output shows the dashboard URL, MCP endpoint, and demo API key.

For development mode (relaxed defaults, permissive policy):

```bash
sudo ephyr init --dev
```

Alternatively, `sudo make setup` provides the same result with Makefile-based customization:

```bash
sudo make setup DASHBOARD_TOKEN=mysecret MCP_PORT=9000 DASHBOARD_PORT=9001
```

Requires Go 1.24+ and systemd. Edit `/etc/ephyr/policy.yaml` to add your targets.

## Connect an Agent

### Claude Code / Claude Desktop

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "ephyr": {
      "type": "url",
      "url": "http://your-broker:8554/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY"
      }
    }
  }
}
```

Works with Claude Code, Claude Desktop, Cursor, Cline, OpenClaw, and any MCP-compatible client.

### CLI

All commands are subcommands of the single `ephyr` binary:

```bash
# Server subcommands
ephyr broker                   # Start the broker server
ephyr signer                   # Start the signer server
ephyr init [--dev]             # Interactive setup wizard

# Agent subcommands
ephyr targets                  # List available SSH targets
ephyr exec webserver \
  --role read \
  -- systemctl status nginx    # Run a command
ephyr session create           # Open persistent session (60x faster)
ephyr services                 # List HTTP proxy services
ephyr remotes                  # List federated MCP servers

# Diagnostics
ephyr status [--restart]       # Health check (services, sockets, endpoints)
ephyr inspect <token>          # Inspect macaroon caveats
ephyr monitor                  # Live broker activity monitoring
ephyr demo                     # Demonstration mode
ephyr host-key                 # SSH host key management
ephyr version                  # Show version
```

## Testing

253+ tests across 13+ test files:

```bash
make test                      # Unit tests
make lint                      # golangci-lint
go test ./test/integration/    # Integration tests (requires running instance)
```

## What's Next

- [How It Works](/docs/how-it-works/) -- understand the access model
- [Architecture](/docs/architecture/) -- security model and process isolation
- [Whitepapers](/whitepapers/architecture/) -- full architecture specification
- [GitHub](https://github.com/EphyrAI/Ephyr) -- source code, issues, and documentation
