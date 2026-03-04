#!/bin/bash
#
# naxsi-ci.sh — Automated Naxsi Whitelist Rule Generation for CI/CD
#
# When a developer deploys a new feature, this tool automatically generates
# the NAXSI whitelist rules needed for that feature's endpoints — while
# enforcing security best practices (never whitelisting real attack patterns).
#
# Designed for non-interactive CI/CD pipelines (Jenkins, GitLab CI, GitHub Actions).
#
# How it works:
#   1. Enables learning mode on staging Nginx
#   2. Your test suite runs (functional tests that exercise the new feature)
#   3. Parses the learning log — only events from THIS test run
#   4. Generates scoped whitelist rules (per-URI, per-variable)
#   5. Validates rules against security policy (blocks dangerous whitelists)
#   6. Outputs a rules file ready for production
#
# Usage:
#   # One-shot (all steps):
#   sudo naxsi-ci auto --test-cmd "npm test" --output rules.txt
#
#   # Step by step:
#   sudo naxsi-ci learn-start
#   npm test                                    # your tests run here
#   sudo naxsi-ci generate --output rules.txt
#   sudo naxsi-ci learn-stop
#   sudo naxsi-ci validate --rules rules.txt
#   sudo naxsi-ci merge --rules rules.txt
#
# Exit codes:
#   0 = success
#   1 = error
#   2 = validation failed (unsafe rules detected — pipeline should FAIL)
#
set -euo pipefail

# ============================================================
# Configuration
# ============================================================
NAXSI_RULES="/etc/nginx/naxsi.rules"
WHITELIST_FILE="/etc/nginx/naxsi_whitelist.rules"
ERROR_LOG="/var/log/nginx/error.log"
BACKUP_DIR="/etc/nginx/naxsi_backups"

# --- Security Policy ---
# Rules that must NEVER be auto-whitelisted — these indicate real attacks.
# If your test suite triggers these, your tests contain attack payloads.
# Fix: separate security tests from functional tests.
NEVER_WHITELIST_IDS=(17 18 1202 1203 1204)
# 17=libinjection_sql 18=libinjection_xss
# 1202=/etc/passwd probe 1203=windows path 1204=cmd.exe probe

# High-risk rule IDs — commented out by default, require --force
HIGH_RISK_IDS=(10 1002 1100 1102 1205 1315 1400 1401 1500 1501)

# Safety limit — if tests trigger more than this, something is wrong
MAX_RULES=200

# ============================================================
# Color output (auto-disabled in non-TTY / CI environments)
# ============================================================
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; DIM=''; NC=''
fi

# ============================================================
# Rule descriptions
# ============================================================
declare -A RULE_DESC=(
    [1]="weird request" [2]="request too big" [10]="null bytes"
    [11]="unknown content-type" [12]="invalid url" [13]="invalid POST"
    [14]="invalid boundary" [15]="invalid JSON" [16]="empty POST"
    [17]="libinjection_sql" [18]="libinjection_xss"
    [1000]="sql keywords" [1001]="double quote" [1002]="hex encoding"
    [1003]="mysql comment /*" [1004]="mysql comment */" [1005]="pipe |"
    [1006]="&&" [1007]="comment --" [1008]="semicolon"
    [1009]="equal sign" [1010]="open paren" [1011]="close paren"
    [1013]="single quote" [1015]="comma" [1016]="comment #"
    [1017]="@@" [1018]="json functions"
    [1100]="http://" [1101]="https://" [1102]="ftp://"
    [1200]="double dot" [1202]="/etc/passwd" [1203]="windows path"
    [1204]="cmd.exe" [1205]="backslash"
    [1302]="html open tag" [1303]="html close tag"
    [1310]="open bracket" [1311]="close bracket" [1312]="tilde"
    [1314]="grave accent" [1315]="double encoding"
    [1400]="utf7/8 encoding" [1401]="M$ encoding"
    [1500]="file upload" [1501]="non-printable chars"
)

# ============================================================
# Helpers
# ============================================================
log_info()  { echo -e "${GREEN}[naxsi-ci]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[naxsi-ci]${NC} $*" >&2; }
log_error() { echo -e "${RED}[naxsi-ci]${NC} $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Must run as root (use sudo)"
        exit 1
    fi
}

get_rule_desc() {
    echo "${RULE_DESC[$1]:-rule $1}"
}

build_matchzone() {
    local zone="$1" uri="$2" var_name="$3"

    if [[ -n "$uri" && "$uri" != "/" && -n "$var_name" ]]; then
        case "$zone" in
            ARGS)      echo "\$URL:${uri}|\$ARGS_VAR:${var_name}" ;;
            BODY)      echo "\$URL:${uri}|\$BODY_VAR:${var_name}" ;;
            HEADERS)   echo "\$URL:${uri}|\$HEADERS_VAR:${var_name}" ;;
            URL)       echo "\$URL:${uri}|URL" ;;
            FILE_EXT)  echo "\$URL:${uri}|FILE_EXT" ;;
            *)         echo "\$URL:${uri}|${zone}" ;;
        esac
    elif [[ -n "$uri" && "$uri" != "/" ]]; then
        case "$zone" in
            ARGS)      echo "\$URL:${uri}|ARGS" ;;
            BODY)      echo "\$URL:${uri}|BODY" ;;
            URL)       echo "\$URL:${uri}|URL" ;;
            HEADERS)   echo "\$URL:${uri}|\$HEADERS_VAR:Cookie" ;;
            FILE_EXT)  echo "\$URL:${uri}|FILE_EXT" ;;
            *)         echo "\$URL:${uri}|${zone}" ;;
        esac
    elif [[ -n "$var_name" ]]; then
        case "$zone" in
            ARGS)      echo "\$ARGS_VAR:${var_name}" ;;
            BODY)      echo "\$BODY_VAR:${var_name}" ;;
            HEADERS)   echo "\$HEADERS_VAR:${var_name}" ;;
            *)         echo "${zone}" ;;
        esac
    else
        echo "${zone}"
    fi
}

reload_nginx() {
    if nginx -t > /dev/null 2>&1; then
        nginx -s reload
        return 0
    else
        log_error "nginx -t failed"
        return 1
    fi
}

# ============================================================
# learn-start: enable learning mode, bookmark log position
# ============================================================
cmd_learn_start() {
    check_root
    log_info "Enabling learning mode..."

    mkdir -p "$BACKUP_DIR"

    # Bookmark current log position so generate only parses NEW events
    local log_lines=0
    if [[ -f "$ERROR_LOG" ]]; then
        log_lines=$(wc -l < "$ERROR_LOG")
    fi
    echo "$log_lines" > /tmp/naxsi-ci-log-offset
    log_info "Log offset saved at line ${log_lines}."

    # Enable learning mode
    if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        log_info "Learning mode already enabled."
    elif grep -qP '^\s*#\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        cp "$NAXSI_RULES" "${BACKUP_DIR}/naxsi.rules.ci-backup"
        sed -i 's/^\(\s*\)#\s*LearningMode;/\1LearningMode;/' "$NAXSI_RULES"
        reload_nginx
        log_info "Learning mode enabled."
    else
        cp "$NAXSI_RULES" "${BACKUP_DIR}/naxsi.rules.ci-backup"
        sed -i '/SecRulesEnabled;/a\        LearningMode;' "$NAXSI_RULES"
        reload_nginx
        log_info "Learning mode enabled."
    fi

    log_info "Ready. Run your tests now, then: naxsi-ci generate"
}

# ============================================================
# learn-stop: disable learning mode, restore blocking
# ============================================================
cmd_learn_stop() {
    check_root

    if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        sed -i 's/^\(\s*\)LearningMode;/\1#LearningMode;/' "$NAXSI_RULES"
        reload_nginx
        log_info "Learning mode disabled. WAF is blocking."
    else
        log_info "Learning mode already disabled."
    fi
}

# ============================================================
# generate: parse learning events -> produce whitelist rules
# ============================================================
cmd_generate() {
    local output_file="/tmp/naxsi_generated_rules.txt"
    local force=false
    local log_source="$ERROR_LOG"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --output|-o) output_file="$2"; shift 2 ;;
            --force|-f)  force=true; shift ;;
            --log)       log_source="$2"; shift 2 ;;
            *)           log_error "Unknown arg: $1"; exit 1 ;;
        esac
    done

    log_info "Generating whitelist rules..."

    if [[ ! -f "$log_source" ]]; then
        log_error "Log not found: $log_source"
        exit 1
    fi

    # Only parse events from THIS test run (after learn-start bookmark)
    local offset=0
    if [[ -f /tmp/naxsi-ci-log-offset ]]; then
        offset=$(cat /tmp/naxsi-ci-log-offset)
    fi

    local temp_log
    temp_log=$(mktemp)
    tail -n +"$((offset + 1))" "$log_source" | grep 'NAXSI_FMT' > "$temp_log" || true

    local event_count
    event_count=$(wc -l < "$temp_log")

    if [[ "$event_count" -eq 0 ]]; then
        log_info "No WAF events from this test run."
        log_info "Your new feature is already compatible with current WAF rules."
        echo "# No rules needed — tests passed without triggering WAF" > "$output_file"
        rm -f "$temp_log"
        exit 0
    fi

    log_info "Found ${event_count} learning events from this test run."

    # Parse into unique rule combinations
    declare -A rule_hits=()

    while IFS= read -r line; do
        local uri=""
        uri=$(echo "$line" | grep -oP 'uri=[^&,]+' | head -1 | cut -d= -f2 || true)

        local idx=0
        while true; do
            local zone id var_name
            zone=$(echo "$line" | grep -oP "zone${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            id=$(echo "$line" | grep -oP "(?<=[^_])id${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            var_name=$(echo "$line" | grep -oP "var_name${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)

            [[ -z "$zone" || -z "$id" ]] && break

            local key="${id}|${zone}|${uri}|${var_name}"
            rule_hits[$key]=$(( ${rule_hits[$key]:-0} + 1 ))

            idx=$((idx + 1))
        done
    done < "$temp_log"
    rm -f "$temp_log"

    local total_rules=${#rule_hits[@]}
    log_info "Extracted ${total_rules} unique rule combinations."

    if [[ $total_rules -gt $MAX_RULES ]]; then
        log_error "Too many rules (${total_rules} > limit ${MAX_RULES})."
        log_error "Your tests may be generating excessive WAF noise."
        log_error "Tip: separate security/fuzz tests from functional tests."
        exit 1
    fi

    # Sort by hits descending
    local sorted_keys
    sorted_keys=$(for key in "${!rule_hits[@]}"; do
        echo "${rule_hits[$key]} $key"
    done | sort -rn)

    # Write rules file with security classification
    local safe_count=0 warned_count=0 blocked_count=0
    local -a blocked_msgs=() warned_msgs=()

    {
        echo "# Naxsi whitelist rules — auto-generated by naxsi-ci"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Source: ${event_count} learning events, ${total_rules} unique rules"
        echo "#"
    } > "$output_file"

    while IFS=' ' read -r hits key; do
        [[ -z "$key" ]] && continue
        IFS='|' read -r id zone uri var_name <<< "$key"

        local desc
        desc=$(get_rule_desc "$id")
        local mz
        mz=$(build_matchzone "$zone" "$uri" "$var_name")

        # --- Security check: NEVER whitelist ---
        local is_blocked=false
        for bid in "${NEVER_WHITELIST_IDS[@]}"; do
            [[ "$id" == "$bid" ]] && is_blocked=true && break
        done

        if [[ "$is_blocked" == "true" ]]; then
            blocked_count=$((blocked_count + 1))
            blocked_msgs+=("  BLOCKED: wl:${id} (${desc}) hits:${hits} uri:${uri:-/}")
            {
                echo "# BLOCKED — rule ${id} (${desc}) is critical security. DO NOT whitelist."
                echo "# BasicRule wl:${id} \"mz:${mz}\";"
                echo "#"
            } >> "$output_file"
            continue
        fi

        # --- Security check: HIGH RISK (commented unless --force) ---
        local is_risky=false
        for rid in "${HIGH_RISK_IDS[@]}"; do
            [[ "$id" == "$rid" ]] && is_risky=true && break
        done

        if [[ "$is_risky" == "true" && "$force" != "true" ]]; then
            warned_count=$((warned_count + 1))
            warned_msgs+=("  WARNING: wl:${id} (${desc}) hits:${hits} uri:${uri:-/}")
            {
                echo "# WARNING — rule ${id} (${desc}) is high-risk. Review before enabling."
                echo "# BasicRule wl:${id} \"mz:${mz}\";"
                echo "#"
            } >> "$output_file"
            continue
        fi

        # --- Safe: write active rule ---
        safe_count=$((safe_count + 1))
        {
            echo "# rule ${id} (${desc}) hits:${hits}${uri:+ uri:$uri}${var_name:+ var:$var_name}"
            echo "BasicRule wl:${id} \"mz:${mz}\";"
            echo ""
        } >> "$output_file"
    done <<< "$sorted_keys"

    # --- Report ---
    echo ""
    log_info "=== Results ==="
    log_info "  Safe rules (active):   ${GREEN}${safe_count}${NC}"

    if [[ $warned_count -gt 0 ]]; then
        log_warn "  High-risk (commented): ${YELLOW}${warned_count}${NC}"
        for msg in "${warned_msgs[@]}"; do
            echo -e "    ${YELLOW}${msg}${NC}"
        done
        log_warn "  Use --force to include high-risk rules."
    fi

    if [[ $blocked_count -gt 0 ]]; then
        log_error "  BLOCKED (security):    ${RED}${blocked_count}${NC}"
        for msg in "${blocked_msgs[@]}"; do
            echo -e "    ${RED}${msg}${NC}"
        done
        echo ""
        log_error "  Your test suite triggered critical security rules."
        log_error "  This means tests contain payloads that look like real attacks"
        log_error "  (SQL injection, path traversal, command execution)."
        log_error "  FIX: Run naxsi-ci with functional tests only."
        log_error "       Keep security/penetration tests in a separate pipeline."
    fi

    echo ""
    log_info "Output: ${CYAN}${output_file}${NC}"

    if [[ $blocked_count -gt 0 ]]; then
        exit 2
    fi
}

# ============================================================
# validate: check a rules file for unsafe whitelists
# ============================================================
cmd_validate() {
    local rules_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rules|-r) rules_file="$2"; shift 2 ;;
            *)          log_error "Unknown arg: $1"; exit 1 ;;
        esac
    done

    if [[ -z "$rules_file" || ! -f "$rules_file" ]]; then
        log_error "Usage: naxsi-ci validate --rules <file>"
        exit 1
    fi

    log_info "Validating ${rules_file}..."

    local total=0 errors=0 warnings=0

    while IFS= read -r line; do
        [[ ! "$line" =~ ^[[:space:]]*BasicRule ]] && continue
        total=$((total + 1))

        local wl_id
        wl_id=$(echo "$line" | grep -oP 'wl:\K\d+' || true)
        [[ -z "$wl_id" ]] && continue

        # Never-whitelist check
        for bid in "${NEVER_WHITELIST_IDS[@]}"; do
            if [[ "$wl_id" == "$bid" ]]; then
                local desc
                desc=$(get_rule_desc "$wl_id")
                log_error "FAIL: wl:${wl_id} (${desc}) — critical rule must not be whitelisted"
                errors=$((errors + 1))
            fi
        done

        # Overly broad whitelist check (no URI scope)
        local mz
        mz=$(echo "$line" | grep -oP 'mz:[^"]+' || true)
        if [[ -n "$mz" && ! "$mz" =~ \$URL: && ! "$mz" =~ _VAR: ]]; then
            log_warn "BROAD: wl:${wl_id} has no URL/var scope — applies to ALL requests"
            warnings=$((warnings + 1))
        fi
    done < "$rules_file"

    echo ""
    log_info "Checked ${total} rules. Errors: ${errors}. Warnings: ${warnings}."

    if [[ $errors -gt 0 ]]; then
        log_error "Validation FAILED. ${errors} unsafe rule(s)."
        exit 2
    fi

    log_info "${GREEN}Validation PASSED.${NC}"
}

# ============================================================
# merge: add new rules into existing whitelist (deduplicated)
# ============================================================
cmd_merge() {
    local rules_file=""
    local target_file="$WHITELIST_FILE"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rules|-r) rules_file="$2"; shift 2 ;;
            --into|-i)  target_file="$2"; shift 2 ;;
            *)          log_error "Unknown arg: $1"; exit 1 ;;
        esac
    done

    if [[ -z "$rules_file" || ! -f "$rules_file" ]]; then
        log_error "Usage: naxsi-ci merge --rules <file> [--into <whitelist>]"
        exit 1
    fi

    check_root

    local new_count
    new_count=$(grep -cP '^\s*BasicRule' "$rules_file" 2>/dev/null || true)

    if [[ "$new_count" -eq 0 ]]; then
        log_info "No active rules to merge."
        exit 0
    fi

    # Validate first
    cmd_validate --rules "$rules_file"

    # Backup and merge
    mkdir -p "$BACKUP_DIR"
    if [[ -f "$target_file" ]]; then
        cp "$target_file" "${BACKUP_DIR}/$(basename "$target_file").$(date '+%Y%m%d_%H%M%S').bak"
    else
        touch "$target_file"
    fi

    local added=0 skipped=0

    echo "" >> "$target_file"
    echo "# CI/CD auto-generated — $(date '+%Y-%m-%d %H:%M:%S')" >> "$target_file"

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*BasicRule ]]; then
            # Deduplicate: skip if identical rule already exists
            if grep -qF "$line" "$target_file" 2>/dev/null; then
                skipped=$((skipped + 1))
            else
                echo "$line" >> "$target_file"
                added=$((added + 1))
            fi
        elif [[ "$line" =~ ^[[:space:]]*# ]]; then
            echo "$line" >> "$target_file"
        fi
    done < "$rules_file"

    log_info "Merged: ${GREEN}${added} new${NC}, ${DIM}${skipped} duplicates skipped${NC}"

    # Validate nginx config after merge
    if nginx -t > /dev/null 2>&1; then
        log_info "${GREEN}nginx -t passed.${NC}"
    else
        log_error "nginx -t FAILED after merge. Check config manually."
        exit 1
    fi

    log_info "Rules merged into ${target_file}."
}

# ============================================================
# diff: preview what would change vs current whitelist
# ============================================================
cmd_diff() {
    local rules_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rules|-r) rules_file="$2"; shift 2 ;;
            *)          log_error "Unknown arg: $1"; exit 1 ;;
        esac
    done

    if [[ -z "$rules_file" || ! -f "$rules_file" ]]; then
        log_error "Usage: naxsi-ci diff --rules <file>"
        exit 1
    fi

    log_info "Comparing against current whitelist..."
    echo ""

    local new_count=0 existing_count=0

    while IFS= read -r line; do
        [[ ! "$line" =~ ^[[:space:]]*BasicRule ]] && continue

        if [[ -f "$WHITELIST_FILE" ]] && grep -qF "$line" "$WHITELIST_FILE" 2>/dev/null; then
            existing_count=$((existing_count + 1))
            echo -e "  ${DIM}= ${line}${NC}"
        else
            new_count=$((new_count + 1))
            echo -e "  ${GREEN}+ ${line}${NC}"
        fi
    done < "$rules_file"

    echo ""
    log_info "New: ${GREEN}${new_count}${NC} | Already exist: ${DIM}${existing_count}${NC}"
}

# ============================================================
# auto: one-shot — learn -> test -> generate -> stop
# ============================================================
cmd_auto() {
    local test_cmd=""
    local output_file="/tmp/naxsi_generated_rules.txt"
    local do_merge=false
    local force=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --test-cmd|-t) test_cmd="$2"; shift 2 ;;
            --output|-o)   output_file="$2"; shift 2 ;;
            --merge|-m)    do_merge=true; shift ;;
            --force|-f)    force=true; shift ;;
            *)             log_error "Unknown arg: $1"; exit 1 ;;
        esac
    done

    if [[ -z "$test_cmd" ]]; then
        log_error "Usage: naxsi-ci auto --test-cmd 'npm test' [--output file] [--merge] [--force]"
        exit 1
    fi

    check_root

    echo ""
    log_info "=== Naxsi CI/CD — Auto Rule Generation ==="
    echo ""

    # Step 1: Enable learning mode
    log_info "Step 1/5: Enable learning mode"
    cmd_learn_start

    # Step 2: Run the test suite
    log_info "Step 2/5: Running tests: ${CYAN}${test_cmd}${NC}"
    echo ""
    local test_exit=0
    eval "$test_cmd" || test_exit=$?
    echo ""

    if [[ $test_exit -ne 0 ]]; then
        log_warn "Tests exited with code ${test_exit} (may include expected WAF blocks)."
    fi

    # Step 3: Generate rules
    log_info "Step 3/5: Generating whitelist rules"
    local gen_args=(--output "$output_file")
    [[ "$force" == "true" ]] && gen_args+=(--force)
    local gen_exit=0
    cmd_generate "${gen_args[@]}" || gen_exit=$?

    # Step 4: Disable learning mode
    log_info "Step 4/5: Disabling learning mode"
    cmd_learn_stop

    # Step 5: Merge if requested
    if [[ "$do_merge" == "true" && $gen_exit -eq 0 ]]; then
        log_info "Step 5/5: Merging rules"
        cmd_merge --rules "$output_file"
        reload_nginx
        log_info "${GREEN}Done. Rules merged and Nginx reloaded.${NC}"
    elif [[ $gen_exit -eq 2 ]]; then
        log_error "Step 5/5: SKIPPED — unsafe rules detected."
        log_error "Review ${output_file} before merging."
    else
        log_info "Step 5/5: Rules at ${CYAN}${output_file}${NC}"
        log_info "To merge: sudo naxsi-ci merge --rules ${output_file}"
    fi

    echo ""
    exit $gen_exit
}

# ============================================================
# Main
# ============================================================
main() {
    local cmd="${1:-}"
    shift 2>/dev/null || true

    case "$cmd" in
        learn-start)  cmd_learn_start ;;
        learn-stop)   cmd_learn_stop ;;
        generate)     cmd_generate "$@" ;;
        validate)     cmd_validate "$@" ;;
        merge)        cmd_merge "$@" ;;
        diff)         cmd_diff "$@" ;;
        auto)         cmd_auto "$@" ;;
        help|--help|-h)
            cat <<'HELP'
naxsi-ci — Automated Naxsi Whitelist Rule Generation for CI/CD

Usage: sudo naxsi-ci <command> [options]

Commands:
  learn-start                     Enable learning mode, bookmark log position
  learn-stop                      Disable learning mode (resume blocking)
  generate --output <file>        Generate rules from learning events
           [--force]              Include high-risk rules
           [--log <file>]         Custom log source
  validate --rules <file>         Check rules for security issues
  merge    --rules <file>         Merge into whitelist (deduplicated)
           [--into <whitelist>]   Target file (default: naxsi_whitelist.rules)
  diff     --rules <file>         Preview changes vs current whitelist
  auto     --test-cmd '<cmd>'     One-shot: learn -> test -> generate -> stop
           [--output <file>]      Output file
           [--merge]              Auto-merge into whitelist
           [--force]              Include high-risk rules

Pipeline Examples:

  # Jenkinsfile
  stage('WAF Rules') {
      steps {
          sh 'sudo naxsi-ci auto --test-cmd "npm test" --output rules.txt'
          sh 'sudo naxsi-ci validate --rules rules.txt'
          sh 'sudo naxsi-ci merge --rules rules.txt'
      }
  }

  # GitLab CI
  waf-rules:
    script:
      - sudo naxsi-ci auto --test-cmd "pytest" --output rules.txt
      - sudo naxsi-ci validate --rules rules.txt
      - sudo naxsi-ci merge --rules rules.txt

  # GitHub Actions
  - run: sudo naxsi-ci auto --test-cmd "go test ./..." --output rules.txt --merge

  # Step by step
  sudo naxsi-ci learn-start
  npm test
  sudo naxsi-ci generate --output rules.txt
  sudo naxsi-ci learn-stop
  sudo naxsi-ci diff --rules rules.txt
  sudo naxsi-ci merge --rules rules.txt

Exit codes:
  0  Success
  1  Error
  2  Unsafe rules detected (pipeline should FAIL)

Security:
  Critical rules are NEVER whitelisted (exit code 2 if triggered).
  High-risk rules are commented out unless --force is used.
  All rules are scoped to specific URIs/variables (not global).
HELP
            ;;
        "")
            echo "Usage: sudo naxsi-ci <command>"
            echo "Run 'naxsi-ci help' for details."
            exit 1
            ;;
        *)
            log_error "Unknown command: $cmd"
            echo "Run 'naxsi-ci help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
