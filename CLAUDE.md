# CLAUDE.md — AI Assistant Guide for naxsi

## Project Overview

This is a **Naxsi WAF (Web Application Firewall) deployment and configuration repository** for Nginx-based infrastructure. It provides an automated installer, WAF rules, high-availability setup with Keepalived, and automatic configuration synchronization between servers.

**Supported platforms:** Ubuntu 22.04 (Jammy), Ubuntu 24.04 (Noble)

**Key components:**
- Naxsi WAF module (v1.6) for Nginx
- Keepalived VRRP for high availability / failover
- Rsync-based configuration synchronization via cron
- LibInjection integration for SQL injection and XSS detection
- One-command automated installer (`install.sh`)

## Repository Structure

```
naxsi/
├── CLAUDE.md              # This file — AI assistant guide
├── ReadMe                 # Installation and setup instructions
├── install.sh             # Automated installer for Ubuntu 22.04/24.04
├── nginx.conf             # Nginx configuration template with Naxsi + security hardening
├── naxsi.rules            # Naxsi WAF runtime rules (thresholds, actions)
├── naxsi_core.rules       # Core WAF detection rules (pattern matching)
├── keepalived.conf        # Keepalived VRRP high-availability configuration template
├── confignginx.txt        # Nginx ./configure flags reference (for manual builds)
├── configsync.sh          # Bash script — syncs config from primary server via rsync
├── check_nginx.sh         # Bash script — Nginx health check for Keepalived
├── block.html             # HTML page displayed when a request is blocked
└── .gitignore             # Excludes binaries, logs, editor files, SSH keys
```

All files are at the root level — there are no subdirectories.

## Quick Start

```bash
# Clone and install on primary server
git clone https://github.com/kiennt048/naxsi.git
cd naxsi
sudo bash install.sh --role primary --vip 192.168.18.70 \
  --backend 10.0.0.2:80 --backend 10.0.0.3:80 \
  --vrrp-password MySecretPass
```

The installer handles: dependency installation, Nginx setup, Naxsi module compilation, configuration deployment, Keepalived setup, and config sync (for backup nodes).

Run `bash install.sh --help` for all options.

## Infrastructure Architecture

```
                      ┌──────────────────┐
                      │   Virtual IP     │
                      │  (Keepalived)    │
                      └────────┬─────────┘
                               │
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐           ┌───────────▼─────────┐
    │   Nginx + Naxsi   │           │   Nginx + Naxsi     │
    │   (Primary)       │◄──rsync──►│   (Backup)          │
    └─────────┬─────────┘           └───────────┬─────────┘
              │                                 │
              └────────────────┬────────────────┘
              ┌────────────────┼────────────────┐
              │                                 │
    ┌─────────▼─────────┐           ┌───────────▼─────────┐
    │  Backend Server 1 │           │  Backend Server 2   │
    └───────────────────┘           └─────────────────────┘
```

## Key Files — Detail

### install.sh — Automated Installer

Full-featured installer script with:
- Ubuntu version detection and validation (22.04, 24.04 only)
- Auto-detection of network interface and server IP
- Naxsi module compilation from source (matches installed Nginx version)
- Dynamic `nginx.conf` generation with security hardening
- Keepalived configuration with generated or user-supplied VRRP password
- Config sync setup with SSH key generation (backup nodes)
- `--uninstall` flag for clean removal
- Colored output and logging to `/var/log/naxsi-install.log`

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

**`nginx.conf`** — Hardened template with:
- Naxsi dynamic module loading
- `server_tokens off` (hides Nginx version)
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`
- TLS 1.2/1.3 only with strong cipher suite
- Proxy headers: `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`
- Connection timeouts configured
- Gzip compression enabled
- Block page served via `internal` directive (not directly accessible)

### High Availability

**`keepalived.conf`** — VRRP instance template with:
- `enable_script_security` to restrict script execution
- `fall 3` / `rise 2` for health check hysteresis (prevents flapping)
- `check_nginx.sh` runs every 2 seconds
- Password placeholder (`CHANGEME`) — never use default passwords

### Synchronization

**`configsync.sh`** — Runs via cron (every minute):
- Uses `set -euo pipefail` for strict error handling
- SSH with `StrictHostKeyChecking=accept-new` and `ConnectTimeout=5`
- Runs `nginx -t` to validate config before reloading
- Logs to `/var/log/naxsi-sync.log` with timestamps

## Build / Compilation

The `install.sh` script handles compilation automatically. For manual builds:

1. Download Naxsi source and Nginx source (must match installed version)
2. `./configure --with-compat --add-dynamic-module=../naxsi-$NAXSI_VER/naxsi_src/`
3. `make modules`
4. Copy `ngx_http_naxsi_module.so` to `/etc/nginx/modules/`

**Build dependencies:** `build-essential`, `libmaxminddb-dev`, `libpcre3-dev`, `libssl-dev`, `zlib1g-dev`

## Deployment Workflow

### Automated (recommended)
1. Clone this repository
2. Run `sudo bash install.sh` with appropriate flags
3. For backup nodes: copy SSH key to primary server

### Manual
1. Clone this repository
2. Edit configuration files for your environment (IPs, interface, passwords)
3. Copy files to system locations (see ReadMe for paths)
4. Set up SSH key authentication between backup and primary servers
5. Configure crontab to run `configsync.sh` every minute
6. Start/restart Nginx and Keepalived services

## Coding Conventions

### Shell Scripts
- Shebang: `#!/bin/bash`
- Use `set -euo pipefail` at the top of scripts
- UPPERCASE for configuration variables and environment variables
- Functions for logical grouping in longer scripts
- Exit codes: `0` = success, `1` = failure
- Log with timestamps when writing to log files
- Quote all variable expansions: `"$VAR"` not `$VAR`

### Nginx Configuration
- 4-space indentation
- `#` for comments, with `# ---` section headers for organization
- `always` flag on security headers
- `internal` directive for error pages (prevents direct access)

### WAF Rules (Naxsi DSL)
- One rule per line
- Format: `MainRule "pattern" "msg:description" "mz:zones" "s:$SCORE:value" id:number;`
- IDs are assigned in 100-block ranges by category
- Patterns use either `str:` (string match) or `rx:` (regex match)
- Match zones: `BODY`, `URL`, `ARGS`, `$HEADERS_VAR:Cookie`, `FILE_EXT`

### File Permissions
- Config files: `644` (owner read/write, group/other read)
- Sensitive config (keepalived): `640`
- Scripts: `755` (health checks) or `750` (sync scripts)
- Never use `777`

## Important Notes for AI Assistants

1. **No test suite exists.** There are no automated tests. Validation is manual: `nginx -t` for config syntax, `curl` for WAF behavior, `systemctl status` for services.
2. **Environment-specific values.** Config files contain example IPs (192.168.18.x). The install script parameterizes these, but the template files in the repo use example values.
3. **Rule ID uniqueness.** When adding new WAF rules, use the next available ID within the appropriate category range. Never reuse an existing ID.
4. **Score thresholds matter.** Changing score values or thresholds in `naxsi.rules` directly impacts what gets blocked. Lower thresholds = more aggressive blocking (more false positives). Higher thresholds = more permissive (potential bypasses).
5. **Learning mode.** Uncomment `LearningMode;` in `naxsi.rules` to switch Naxsi to learning mode (log but don't block). Useful for tuning rules on production traffic.
6. **install.sh is the source of truth** for deployment logic. If deployment steps change, update `install.sh` — the ReadMe references it.
7. **Binary files excluded.** The `.gitignore` excludes `*.so` files. The install script compiles the module from source, so pre-built binaries are no longer needed in the repo.
8. **Security-sensitive defaults.** Keepalived password is set to `CHANGEME` in the template. The install script generates a random password if none is provided. Never commit real passwords.
