# CLAUDE.md — AI Assistant Guide for naxsi

## Project Overview

This is a **Naxsi WAF (Web Application Firewall) deployment and configuration repository** for Nginx-based infrastructure. It provides an automated installer, WAF rules, high-availability setup with Keepalived, and automatic configuration synchronization between servers.

**Supported platforms:** Ubuntu 22.04 (Jammy), Ubuntu 24.04 (Noble)

**Key components:**
- Naxsi WAF module (v1.7) for Nginx
- Extended blocking rules (scanners, web security, PHP, SQL, WordPress)
- Interactive learning mode & whitelist manager (`naxsi-manager.sh`)
- Keepalived VRRP for high availability / failover
- Rsync-based configuration synchronization via cron
- LibInjection integration for SQL injection and XSS detection
- One-command automated installer (`install.sh`)

## Repository Structure

```
naxsi/
├── CLAUDE.md                        # This file — AI assistant guide
├── ReadMe                           # Installation and setup instructions
├── install.sh                       # Automated installer for Ubuntu 22.04/24.04
├── naxsi-manager.sh                 # Interactive learning mode & whitelist manager
├── naxsi-ai-agent.sh                # AI security agent — autonomous log analysis & decisions
├── naxsi-ci.sh                      # CI/CD auto rule generation (Jenkins/GitLab/GitHub Actions)
├── nginx.conf                       # Nginx configuration template
├── naxsi.rules                      # Naxsi WAF runtime rules (thresholds)
├── naxsi_core.rules                 # Core WAF detection rules (pattern matching)
├── naxsi_blocking_scanner.rules     # Scanner/bot blocking rules (from upstream 1.7)
├── naxsi_blocking_web.rules         # Web security rules — CVEs, probes (from upstream 1.7)
├── naxsi_blocking_wordpress.rules   # WordPress-specific rules (from upstream 1.7)
├── naxsi_blocking_php.rules         # PHP security rules (from upstream 1.7)
├── naxsi_blocking_sql.rules         # Advanced SQL injection rules (from upstream 1.7)
├── keepalived.conf                  # Keepalived VRRP HA configuration template
├── confignginx.txt                  # Nginx ./configure flags reference
├── configsync.sh                    # Bash script — syncs config from primary via rsync
├── check_nginx.sh                   # Bash script — Nginx health check for Keepalived
├── block.html                       # HTML page displayed when a request is blocked
└── .gitignore                       # Excludes binaries, logs, editor files, SSH keys
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

# Then tune with the interactive manager
sudo naxsi-manager
```

The installer handles: dependency installation, Nginx setup, Naxsi 1.7 module compilation, blocking rules deployment, configuration deployment, Keepalived setup, naxsi-manager install, and config sync (for backup nodes).

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
- Naxsi 1.7 module compilation from source (matches installed Nginx version)
- Blocking rules deployment (scanner, web security, PHP, SQL, WordPress)
- Dynamic `nginx.conf` generation with security hardening
- naxsi-manager installation for learning mode & whitelist management
- AI security agent installation for autonomous log analysis
- Keepalived configuration with generated or user-supplied VRRP password
- Config sync setup with SSH key generation (backup nodes)
- `--uninstall` flag for clean removal
- Colored output and logging to `/var/log/naxsi-install.log`

### naxsi-manager.sh — Learning Mode & Whitelist Manager

Interactive CLI tool (`sudo naxsi-manager`) for:
- Toggling learning mode on/off (modifies `naxsi.rules`, reloads Nginx)
- Parsing Nginx error log to extract NAXSI_FMT learning events
- **Hit count statistics**: shows how many times each rule was triggered and from how many unique IPs — helps distinguish legitimate traffic from attacks
- **Log statistics** (`stats` command): top triggered rule IDs, top URIs, unique IP analysis — without generating rules
- Generating whitelist rules (`BasicRule wl:ID "mz:ZONE";`) sorted by hit frequency
- Interactive rule-by-rule review with hit counts: accept / reject / edit
- Applying approved rules to `naxsi_whitelist.rules` and reloading Nginx
- Removing individual whitelist rules
- Automatic backups before any config change

### naxsi-ai-agent.sh — AI Security Agent

On-demand security analysis tool (`sudo naxsi-ai-agent`) that acts as an autonomous security engineer:

- **Analyze** (`analyze`): One-shot log analysis — classifies every rule trigger as SAFE, SUSPICIOUS, or ATTACK with detailed reasoning
- **Auto-whitelist** (`auto-whitelist`): Applies only rules classified as SAFE (high hits + many unique IPs + low/medium risk). Requires confirmation before applying
- **Investigate** (`investigate <ip-or-uri>`): Explains why a specific IP or URI is being blocked — shows triggered rules, risk levels, IP diversity, and a recommendation
- **Request** (`request <ip> [uri]`): User requests access — agent independently decides APPROVE/DENY with explanation. Does NOT blindly follow user requests
- **Report** (`report`): Security summary with top blocked IPs, top rules, decision history
- **Policy** (`policy`): Shows current security thresholds and decision framework

**Design philosophy — on-demand, not real-time:**
- All commands are one-shot (run, analyze, exit) — no persistent process, no ongoing cost
- User starts the agent when they have accumulated logs, agent processes everything at once
- When a user reports a problem, the operator runs `investigate` or `request` with the user's IP
- The agent makes independent security decisions — it will DENY requests that trigger critical rules even if the user insists

**Security policy thresholds** (configurable at top of script):
- Auto-whitelist requires ≥50 hits AND ≥10 unique IPs
- Rules 17, 18, 1202, 1203, 1204 are NEVER auto-whitelisted (libinjection, path probes)
- Single-IP dominance (>80% of hits from one source) triggers SUSPICIOUS classification
- Each rule has a risk level: low, medium, high, critical

**State files:**
- Agent log: `/var/log/naxsi-ai-agent.log`
- Decision history: `/var/lib/naxsi-ai-agent/decisions.log`

### naxsi-ci.sh — CI/CD Auto Rule Generation

Non-interactive tool (`sudo naxsi-ci`) for automated whitelist rule generation in CI/CD pipelines:

- **learn-start**: Enables learning mode and bookmarks log position (only new events are parsed)
- **generate**: Parses learning events from the current test run, produces scoped whitelist rules
- **validate**: Checks rules against security policy (blocks critical rules, warns on high-risk)
- **merge**: Adds new rules to whitelist with deduplication and `nginx -t` validation
- **diff**: Preview new rules vs existing whitelist
- **auto**: One-shot mode — learn -> run tests -> generate -> stop learning

**Security enforcement:**
- Critical rules (17, 18, 1202, 1203, 1204) are NEVER whitelisted — pipeline exits with code 2
- High-risk rules are commented out by default (require `--force`)
- All generated rules are scoped to specific URIs/variables (not global)
- If tests trigger >200 rules, generation fails (safety limit)

**Key design: functional tests, not security tests.** The tool expects you to run your app's normal functional/integration test suite (which exercises real endpoints). Security/penetration tests should be in a separate pipeline — they would trigger critical rules and cause the pipeline to fail intentionally.

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

**Blocking rules** (from Naxsi 1.7 upstream):

| File                                | ID Range        | Category              |
|-------------------------------------|-----------------|-----------------------|
| `naxsi_blocking_scanner.rules`      | 10000000+       | Scanners, bots, tools |
| `naxsi_blocking_web.rules`          | 20000000+       | CVEs, exposed services|
| `naxsi_blocking_wordpress.rules`    | 30000000+       | WordPress attacks     |
| `naxsi_blocking_php.rules`          | 40000000+       | PHP security          |
| `naxsi_blocking_sql.rules`          | 50000000+       | Advanced SQL injection|

Blocking rules use `$UWA` (Unwanted Access) score variable.

**`naxsi.rules`** — Runtime configuration with blocking thresholds:
- `$SQL >= 8` → BLOCK
- `$RFI >= 8` → BLOCK
- `$TRAVERSAL >= 5` → BLOCK
- `$UPLOAD >= 5` → BLOCK
- `$XSS >= 8` → BLOCK
- `$UWA >= 8` → BLOCK
- `$EVADE >= 4` → BLOCK

LibInjection is enabled for both SQL and XSS detection. Learning mode is available but disabled by default.

**`naxsi_whitelist.rules`** — User-managed whitelist (created empty, populated via naxsi-manager).

### Nginx Configuration

**`nginx.conf`** — Hardened template with:
- Naxsi dynamic module loading
- Core rules + blocking rules included at `http` level
- Runtime rules + whitelist included at `location` level
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

1. Download Naxsi 1.7 source and Nginx source (must match installed version)
2. `./configure --with-compat --add-dynamic-module=../naxsi-$NAXSI_VER/naxsi_src/`
3. `make modules`
4. Copy `ngx_http_naxsi_module.so` to `/etc/nginx/modules/`

**Build dependencies:** `build-essential`, `libmaxminddb-dev`, `libpcre3-dev`, `libssl-dev`, `zlib1g-dev`

## Deployment Workflow

### Automated (recommended)
1. Clone this repository
2. Run `sudo bash install.sh` with appropriate flags
3. For backup nodes: copy SSH key to primary server
4. Run `sudo naxsi-manager` to tune whitelists via learning mode

### Manual
1. Clone this repository
2. Edit configuration files for your environment (IPs, interface, passwords)
3. Copy files to system locations (see ReadMe for paths)
4. Set up SSH key authentication between backup and primary servers
5. Configure crontab to run `configsync.sh` every minute
6. Start/restart Nginx and Keepalived services
7. Use `sudo naxsi-manager` for learning mode and whitelist management

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
- Core rules: IDs in 100-block ranges by category
- Blocking rules: IDs in 10000000-block ranges by category
- Patterns use either `str:` (string match) or `rx:` (regex match)
- Match zones: `BODY`, `URL`, `ARGS`, `$HEADERS_VAR:Cookie`, `FILE_EXT`, `ANY`
- Whitelist format: `BasicRule wl:ID "mz:ZONE";`

### File Permissions
- Config files: `644` (owner read/write, group/other read)
- Sensitive config (keepalived): `640`
- Scripts: `755` (health checks, manager) or `750` (sync scripts)
- Never use `777`

## Important Notes for AI Assistants

1. **No test suite exists.** There are no automated tests. Validation is manual: `nginx -t` for config syntax, `curl` for WAF behavior, `systemctl status` for services.
2. **Environment-specific values.** Config files contain example IPs (192.168.18.x). The install script parameterizes these, but the template files in the repo use example values.
3. **Rule ID uniqueness.** When adding new WAF rules, use the next available ID within the appropriate category range. Never reuse an existing ID.
4. **Score thresholds matter.** Changing score values or thresholds in `naxsi.rules` directly impacts what gets blocked. Lower thresholds = more aggressive blocking (more false positives). Higher thresholds = more permissive (potential bypasses).
5. **Learning mode.** Use `sudo naxsi-manager learn-on` or uncomment `LearningMode;` in `naxsi.rules` to switch Naxsi to learning mode (log but don't block). Use `naxsi-manager generate` to create whitelist rules from logs.
6. **install.sh is the source of truth** for deployment logic. If deployment steps change, update `install.sh` — the ReadMe references it.
7. **Binary files excluded.** The `.gitignore` excludes `*.so` files. The install script compiles the module from source.
8. **Security-sensitive defaults.** Keepalived password is set to `CHANGEME` in the template. The install script generates a random password if none is provided. Never commit real passwords.
9. **Blocking rules from upstream.** The `naxsi_blocking_*.rules` files come directly from Naxsi 1.7 upstream repository. WordPress blocking rules are disabled by default in `nginx.conf`.
10. **naxsi-manager modifies live config.** The manager edits `naxsi.rules` and `naxsi_whitelist.rules` in `/etc/nginx/`. It creates backups in `/etc/nginx/naxsi_backups/` before each change.
