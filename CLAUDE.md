# CLAUDE.md — AI Assistant Guide for naxsi

## Project Overview

This is a **Naxsi WAF (Web Application Firewall) deployment and configuration repository** for Nginx-based infrastructure. It provides ready-to-use configuration files, WAF rules, high-availability setup with Keepalived, and automatic configuration synchronization between servers.

**Key components:**
- Naxsi WAF module (v1.6) for Nginx 1.18.0
- Keepalived VRRP for high availability / failover
- Rsync-based configuration synchronization via cron
- LibInjection integration for SQL injection and XSS detection

This is **not** a compiled source project — it is a deployment configuration repository containing pre-built binaries and configuration files.

## Repository Structure

```
naxsi/
├── CLAUDE.md              # This file — AI assistant guide
├── ReadMe                 # Installation and setup instructions
├── nginx.conf             # Main Nginx configuration with Naxsi integration
├── naxsi.rules            # Naxsi WAF runtime rules (thresholds, actions)
├── naxsi_core.rules       # Core WAF detection rules (pattern matching)
├── keepalived.conf        # Keepalived VRRP high-availability configuration
├── confignginx.txt        # Nginx ./configure flags reference
├── configsync.sh          # Bash script — syncs config from main server via rsync
├── check_nginx.sh         # Bash script — Nginx health check for Keepalived
├── block.html             # HTML page displayed when a request is blocked
└── ngx_http_naxsi_module.so  # Pre-compiled Naxsi dynamic module (ELF 64-bit)
```

All files are at the root level — there are no subdirectories.

## Infrastructure Architecture

```
                      ┌──────────────────┐
                      │   Virtual IP     │
                      │  192.168.18.70   │
                      │   (Keepalived)   │
                      └────────┬─────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐           ┌───────────▼─────────┐
    │   Nginx + Naxsi   │           │   Nginx + Naxsi     │
    │   (Primary)       │◄──rsync──►│   (Backup)          │
    │   192.168.18.71   │           │   192.168.18.72      │
    └─────────┬─────────┘           └───────────┬─────────┘
              │                                 │
              └────────────────┬────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐           ┌───────────▼─────────┐
    │  Backend Server 1 │           │  Backend Server 2   │
    │  192.168.18.61:80 │           │  192.168.18.62:80   │
    └───────────────────┘           └─────────────────────┘
```

## Key Files — Detail

### WAF Rules

**`naxsi_core.rules`** — Core detection patterns organized by rule ID ranges:

| ID Range    | Category            | Score Variable |
|-------------|---------------------|----------------|
| 1–999       | Internal errors     | (various)      |
| 1000–1099   | SQL Injection       | `$SQL`         |
| 1100–1199   | Remote File Inclusion (RFI) | `$RFI` |
| 1200–1299   | Directory Traversal | `$TRAVERSAL`   |
| 1300–1399   | Cross-Site Scripting (XSS) | `$XSS`  |
| 1400–1500   | Evasion Tricks      | `$EVADE`       |
| 1500–1600   | File Uploads        | `$UPLOAD`      |

Rule format: `MainRule "pattern" "msg:description" "mz:match_zones" "s:$SCORE:value" id:number;`

**`naxsi.rules`** — Runtime configuration with blocking thresholds:
- `$SQL >= 8` → BLOCK
- `$RFI >= 8` → BLOCK
- `$TRAVERSAL >= 5` → BLOCK
- `$UPLOAD >= 5` → BLOCK
- `$XSS >= 8` → BLOCK

LibInjection is enabled for both SQL and XSS detection. Learning mode is available but disabled by default.

### Nginx Configuration

**`nginx.conf`** — Loads the Naxsi dynamic module, includes core rules at the `http` block level, and includes runtime rules at the `location` block level. Upstream backends are load-balanced. Blocked requests are proxied to a block page.

### High Availability

**`keepalived.conf`** — VRRP instance with virtual IP 192.168.18.70. Uses `check_nginx.sh` every 2 seconds to verify Nginx is running. Failover between primary and backup servers is automatic.

### Synchronization

**`configsync.sh`** — Runs via cron (every minute). Uses rsync over SSH to pull Nginx config from the main server. Reloads Nginx only when changes are detected.

## Build / Compilation

The Naxsi module is compiled outside this repository. The process (documented in `ReadMe`) is:

1. Download Naxsi v1.6 source and Nginx 1.18.0 source
2. Run `./configure` with flags from `confignginx.txt` including `--add-dynamic-module=../naxsi-$NAXSI_VER/naxsi_src/`
3. Run `make modules`
4. Copy resulting `ngx_http_naxsi_module.so` to `/etc/nginx/modules/`

**Build dependencies:** `build-essential`, `libmaxminddb-dev`, `libpcre3-dev`, `libssl-dev`, `zlib1g-dev`

## Deployment Workflow

1. Clone this repository
2. Edit configuration files for your environment (IPs, hostnames, SSH keys)
3. Copy files to system locations:
   - `nginx.conf`, `naxsi.rules`, `naxsi_core.rules` → `/etc/nginx/`
   - `keepalived.conf`, `check_nginx.sh` → `/etc/keepalived/`
   - `block.html` → `/var/www/html/`
   - `ngx_http_naxsi_module.so` → `/etc/nginx/modules/`
4. Set up SSH key authentication between backup and main servers
5. Configure crontab to run `configsync.sh` every minute
6. Start/restart Nginx and Keepalived services

## Coding Conventions

### Shell Scripts
- Use `#!/bin/bash` (or `#!/bin/sh` for simple scripts)
- UPPERCASE for environment variables (e.g., `RSYNC`)
- Simple exit codes: `0` for success, `1` for failure
- Minimal error handling — pragmatic approach

### Nginx Configuration
- 4-space indentation
- `#` for comments
- Inline comments to explain non-obvious settings

### WAF Rules (Naxsi DSL)
- One rule per line
- Format: `MainRule "pattern" "msg:description" "mz:zones" "s:$SCORE:value" id:number;`
- IDs are assigned in 100-block ranges by category
- Patterns use either `str:` (string match) or `rx:` (regex match)
- Match zones: `BODY`, `URL`, `ARGS`, `$HEADERS_VAR:Cookie`, `FILE_EXT`

### General
- No formal linting, testing, or CI/CD pipelines
- Manual testing and verification
- Documentation is in the `ReadMe` file (plain text, no markdown extension)

## Important Notes for AI Assistants

1. **No test suite exists.** There are no automated tests to run. Validation is manual (restart Nginx, check logs, test with curl).
2. **Sensitive values present.** Configuration files contain hardcoded IP addresses, SSH paths, and a Keepalived password (`1234`). Do not expose these in public contexts without the owner's consent.
3. **Binary file.** `ngx_http_naxsi_module.so` is a pre-compiled ELF binary — do not attempt to edit it.
4. **Environment-specific.** Most configuration references specific IPs (192.168.18.x) and user paths (`/home/kien/`). Changes must be adapted to the target environment.
5. **Rule ID uniqueness.** When adding new WAF rules, use the next available ID within the appropriate category range. Never reuse an existing ID.
6. **Score thresholds matter.** Changing score values or thresholds in `naxsi.rules` directly impacts what gets blocked. Lower thresholds = more aggressive blocking (more false positives). Higher thresholds = more permissive (potential bypasses).
7. **Learning mode.** Uncomment `LearningMode;` in `naxsi.rules` to switch Naxsi to learning mode (log but don't block). This is useful for tuning rules on production traffic.
