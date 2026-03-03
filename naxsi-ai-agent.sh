#!/bin/bash
#
# naxsi-ai-agent.sh — AI-powered Security Agent for Naxsi WAF
#
# Autonomous security agent that:
#   1. Analyzes Naxsi WAF logs and classifies traffic patterns
#   2. Auto-generates whitelist rules for safe traffic (high confidence)
#   3. Investigates why a specific IP/URI is being blocked
#   4. Makes independent security decisions (approve/deny) with explanations
#   5. Runs continuously via cron or as a daemon
#
# The agent acts as an autonomous security engineer — it does NOT blindly
# follow user requests. It evaluates each case against security policy
# and explains its reasoning.
#
# Usage:
#   sudo naxsi-ai-agent analyze               Analyze logs, output JSON report
#   sudo naxsi-ai-agent auto-whitelist        Auto-apply safe whitelist rules
#   sudo naxsi-ai-agent investigate <ip>      Why is this IP being blocked?
#   sudo naxsi-ai-agent investigate <uri>     Why is this URI triggering rules?
#   sudo naxsi-ai-agent request <ip> <uri>    User requests access — agent decides
#   sudo naxsi-ai-agent daemon                Run continuously (check every 5 min)
#   sudo naxsi-ai-agent report                Generate security report
#   sudo naxsi-ai-agent policy                Show current security policy
#
set -euo pipefail

# ============================================================
# Configuration
# ============================================================
NAXSI_RULES="/etc/nginx/naxsi.rules"
WHITELIST_FILE="/etc/nginx/naxsi_whitelist.rules"
PENDING_FILE="/etc/nginx/naxsi_whitelist_pending.rules"
ERROR_LOG="/var/log/nginx/error.log"
ACCESS_LOG="/var/log/nginx/access.log"
BACKUP_DIR="/etc/nginx/naxsi_backups"
AGENT_LOG="/var/log/naxsi-ai-agent.log"
AGENT_STATE="/var/lib/naxsi-ai-agent"
DECISIONS_LOG="${AGENT_STATE}/decisions.log"
REPORT_DIR="${AGENT_STATE}/reports"

# --- Security Policy Thresholds ---
# These define the agent's decision-making rules.
# Adjust these to make the agent more or less strict.

# Minimum hits required before auto-whitelisting (legitimate traffic signal)
MIN_HITS_AUTO_WHITELIST=50

# Minimum unique IPs required (diversity = likely legitimate)
MIN_IPS_AUTO_WHITELIST=10

# Rule IDs that should NEVER be auto-whitelisted (always require human review)
# These are high-risk rules where false positives are rare
NEVER_AUTO_WHITELIST=(17 18 1202 1203 1204)
# 17 = libinjection_sql, 18 = libinjection_xss
# 1202 = /etc/passwd probe, 1203 = windows path, 1204 = cmd.exe probe

# Maximum hits from a single IP before it's flagged as suspicious
# (one source hammering a rule = potential attack, not legitimate traffic)
SINGLE_IP_SUSPICION_THRESHOLD=100

# Ratio: if >80% of hits come from one IP, it's suspicious
SINGLE_IP_RATIO_THRESHOLD=80

# Daemon check interval in seconds
DAEMON_INTERVAL=300

# ============================================================
# Color output
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# Rule descriptions (same as naxsi-manager)
# ============================================================
declare -A RULE_DESC=(
    [1]="weird request, unable to parse"
    [2]="request too big, stored on disk"
    [10]="invalid hex encoding, null bytes"
    [11]="unknown content-type"
    [12]="invalid formatted url"
    [13]="invalid POST format"
    [14]="invalid POST boundary"
    [15]="invalid JSON"
    [16]="empty POST"
    [17]="libinjection_sql"
    [18]="libinjection_xss"
    [1000]="sql keywords"
    [1001]="double quote"
    [1002]="0x, possible hex encoding"
    [1003]="mysql comment (/*)"
    [1004]="mysql comment (*/)"
    [1005]="mysql keyword (|)"
    [1006]="mysql keyword (&&)"
    [1007]="mysql comment (--)"
    [1008]="semicolon"
    [1009]="equal sign in var"
    [1010]="open parenthesis"
    [1011]="close parenthesis"
    [1013]="simple quote"
    [1015]="comma"
    [1016]="mysql comment (#)"
    [1017]="double arobase (@@)"
    [1018]="json functions"
    [1100]="http:// scheme"
    [1101]="https:// scheme"
    [1102]="ftp:// scheme"
    [1200]="double dot"
    [1202]="obvious probe (/etc/passwd)"
    [1203]="obvious windows path"
    [1204]="obvious probe (cmd.exe)"
    [1205]="backslash"
    [1302]="html open tag"
    [1303]="html close tag"
    [1310]="open square bracket"
    [1311]="close square bracket"
    [1312]="tilde character"
    [1314]="grave accent"
    [1315]="double encoding"
    [1400]="utf7/8 encoding"
    [1401]="M$ encoding"
    [1500]="asp/php/jsp file upload"
    [1501]="non-printable filename chars"
)

# Risk level per rule — how dangerous is it to whitelist this rule?
# low = commonly triggers on legitimate traffic (safe to auto-whitelist)
# medium = sometimes legitimate, sometimes attack (needs context)
# high = rarely triggers on legitimate traffic (likely real attack)
# critical = almost always a real attack (never auto-whitelist)
declare -A RULE_RISK=(
    [1]="medium" [2]="low" [10]="high" [11]="low" [12]="medium"
    [13]="low" [14]="low" [15]="low" [16]="low"
    [17]="critical" [18]="critical"
    [1000]="medium" [1001]="low" [1002]="medium" [1003]="medium"
    [1004]="medium" [1005]="low" [1006]="medium" [1007]="medium"
    [1008]="low" [1009]="low" [1010]="medium" [1011]="medium"
    [1013]="low" [1015]="low" [1016]="medium" [1017]="medium"
    [1018]="low"
    [1100]="medium" [1101]="low" [1102]="high"
    [1200]="medium" [1202]="critical" [1203]="critical" [1204]="critical"
    [1205]="medium"
    [1302]="medium" [1303]="medium" [1310]="low" [1311]="low"
    [1312]="low" [1314]="low" [1315]="high"
    [1400]="high" [1401]="high"
    [1500]="high" [1501]="high"
)

# ============================================================
# Helpers
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo).${NC}"
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "$BACKUP_DIR" "$AGENT_STATE" "$REPORT_DIR"
    touch "$WHITELIST_FILE" "$AGENT_LOG" "$DECISIONS_LOG"
    chmod 644 "$WHITELIST_FILE"
}

log_agent() {
    local level="$1" msg="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$AGENT_LOG"
}

log_decision() {
    local action="$1" rule_id="$2" reason="$3"
    local entry="[$(date '+%Y-%m-%d %H:%M:%S')] action=$action rule_id=$rule_id reason=\"$reason\""
    echo "$entry" >> "$DECISIONS_LOG"
    log_agent "DECISION" "$entry"
}

get_rule_description() {
    local id="$1"
    echo "${RULE_DESC[$id]:-unknown rule}"
}

get_rule_risk() {
    local id="$1"
    echo "${RULE_RISK[$id]:-medium}"
}

backup_file() {
    local file="$1"
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    if [[ -f "$file" ]]; then
        cp "$file" "${BACKUP_DIR}/$(basename "$file").${timestamp}.bak"
    fi
}

reload_nginx() {
    if nginx -t > /dev/null 2>&1; then
        nginx -s reload
        log_agent "INFO" "Nginx reloaded successfully"
        return 0
    else
        log_agent "ERROR" "Nginx config test failed — changes NOT applied"
        return 1
    fi
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

# ============================================================
# Log Parsing
# ============================================================

# Globals populated by parse_logs
declare -A LOG_RULE_HITS=()       # "id|zone|uri|var" -> hit count
declare -A LOG_RULE_IPS=()        # "id|zone|uri|var" -> "ip1 ip2 ..."
declare -A LOG_RULE_IP_HITS=()    # "id|zone|uri|var|ip" -> hits from that IP
declare -A LOG_ID_TOTAL=()        # rule_id -> total hits
declare -A LOG_URI_TOTAL=()       # uri -> total hits
declare -A LOG_IP_TOTAL=()        # ip -> total hits
LOG_TOTAL_EVENTS=0
LOG_UNIQUE_IPS=0

parse_logs() {
    LOG_RULE_HITS=()
    LOG_RULE_IPS=()
    LOG_RULE_IP_HITS=()
    LOG_ID_TOTAL=()
    LOG_URI_TOTAL=()
    LOG_IP_TOTAL=()
    LOG_TOTAL_EVENTS=0

    local -A all_ips=()
    local log_source="${1:-$ERROR_LOG}"

    if [[ ! -f "$log_source" ]]; then
        return
    fi

    while IFS= read -r line; do
        LOG_TOTAL_EVENTS=$((LOG_TOTAL_EVENTS + 1))

        local uri="" ip=""
        uri=$(echo "$line" | grep -oP 'uri=[^&,]+' | head -1 | cut -d= -f2 || true)
        ip=$(echo "$line" | grep -oP 'ip=[^&,]+' | head -1 | cut -d= -f2 || true)

        [[ -n "$ip" ]] && all_ips[$ip]=1
        [[ -n "$ip" ]] && LOG_IP_TOTAL[$ip]=$(( ${LOG_IP_TOTAL[$ip]:-0} + 1 ))
        [[ -n "$uri" ]] && LOG_URI_TOTAL[$uri]=$(( ${LOG_URI_TOTAL[$uri]:-0} + 1 ))

        local idx=0
        while true; do
            local zone id var_name
            zone=$(echo "$line" | grep -oP "zone${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            id=$(echo "$line" | grep -oP "(?<=[^_])id${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            var_name=$(echo "$line" | grep -oP "var_name${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)

            [[ -z "$zone" || -z "$id" ]] && break

            local key="${id}|${zone}|${uri}|${var_name}"
            LOG_RULE_HITS[$key]=$(( ${LOG_RULE_HITS[$key]:-0} + 1 ))
            LOG_ID_TOTAL[$id]=$(( ${LOG_ID_TOTAL[$id]:-0} + 1 ))

            # Track per-IP hits for this rule
            if [[ -n "$ip" ]]; then
                LOG_RULE_IP_HITS["${key}|${ip}"]=$(( ${LOG_RULE_IP_HITS["${key}|${ip}"]:-0} + 1 ))
                local existing="${LOG_RULE_IPS[$key]:-}"
                if [[ ! " $existing " =~ " $ip " ]]; then
                    LOG_RULE_IPS[$key]="${existing} ${ip}"
                fi
            fi

            idx=$((idx + 1))
        done
    done < <(grep 'NAXSI_FMT' "$log_source")

    LOG_UNIQUE_IPS=${#all_ips[@]}
}

# ============================================================
# Security Analysis Engine
# ============================================================

# Classify a rule trigger as: SAFE, SUSPICIOUS, or ATTACK
# Returns the classification and a reason string
classify_rule() {
    local key="$1"
    local hits="${LOG_RULE_HITS[$key]:-0}"

    IFS='|' read -r id zone uri var_name <<< "$key"

    local risk
    risk=$(get_rule_risk "$id")
    local desc
    desc=$(get_rule_description "$id")

    # Count unique IPs
    local ip_list="${LOG_RULE_IPS[$key]:-}"
    local ip_count=0
    if [[ -n "$ip_list" ]]; then
        ip_count=$(echo "$ip_list" | tr ' ' '\n' | grep -c . || true)
    fi

    # Find the top IP's contribution
    local max_ip_hits=0
    local max_ip=""
    for ip_key in "${!LOG_RULE_IP_HITS[@]}"; do
        if [[ "$ip_key" == "${key}|"* ]]; then
            local this_hits="${LOG_RULE_IP_HITS[$ip_key]}"
            if [[ $this_hits -gt $max_ip_hits ]]; then
                max_ip_hits=$this_hits
                max_ip="${ip_key##*|}"
            fi
        fi
    done

    local single_ip_pct=0
    if [[ $hits -gt 0 ]]; then
        single_ip_pct=$((max_ip_hits * 100 / hits))
    fi

    # --- Decision Logic ---

    # CRITICAL rules: never auto-whitelist
    if [[ "$risk" == "critical" ]]; then
        echo "ATTACK|Critical rule $id ($desc) triggered $hits times — this is almost always a real attack. Manual review required."
        return
    fi

    # High risk + low diversity = likely attack
    if [[ "$risk" == "high" && $ip_count -lt 3 ]]; then
        echo "ATTACK|High-risk rule $id ($desc) triggered by only $ip_count IP(s) — insufficient diversity to confirm as legitimate."
        return
    fi

    # Single IP dominates (>80% of hits from one source)
    if [[ $single_ip_pct -ge $SINGLE_IP_RATIO_THRESHOLD && $hits -ge 10 ]]; then
        echo "SUSPICIOUS|$single_ip_pct% of hits from single IP $max_ip ($max_ip_hits/$hits) — possible targeted attack or bot. Needs investigation."
        return
    fi

    # Single IP hammering
    if [[ $max_ip_hits -ge $SINGLE_IP_SUSPICION_THRESHOLD && $ip_count -le 2 ]]; then
        echo "SUSPICIOUS|Single IP $max_ip generated $max_ip_hits hits on rule $id — excessive volume from one source."
        return
    fi

    # Low hits = not enough data
    if [[ $hits -lt $MIN_HITS_AUTO_WHITELIST ]]; then
        echo "SUSPICIOUS|Only $hits hits (minimum $MIN_HITS_AUTO_WHITELIST required) — insufficient data to auto-whitelist. Wait for more traffic."
        return
    fi

    # Low IP diversity
    if [[ $ip_count -lt $MIN_IPS_AUTO_WHITELIST ]]; then
        echo "SUSPICIOUS|Only $ip_count unique IPs (minimum $MIN_IPS_AUTO_WHITELIST required) — insufficient diversity."
        return
    fi

    # Passed all checks: SAFE to whitelist
    echo "SAFE|Rule $id ($desc): $hits hits from $ip_count IPs across ${zone}${uri:+ at $uri}${var_name:+ var=$var_name}. High volume, diverse sources — legitimate traffic pattern."
}

# ============================================================
# Commands
# ============================================================

# --- Analyze: produce a structured analysis ---
cmd_analyze() {
    echo ""
    echo -e "${BOLD}=== AI Security Agent — Log Analysis ===${NC}"
    echo ""

    if [[ ! -f "$ERROR_LOG" ]]; then
        echo -e "${RED}Error log not found: ${ERROR_LOG}${NC}"
        return 1
    fi

    local raw_count
    raw_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)
    if [[ "$raw_count" -eq 0 ]]; then
        echo -e "${GREEN}No WAF events in log. All traffic is clean.${NC}"
        log_agent "INFO" "Analysis complete: no events found"
        return
    fi

    echo -e "Parsing ${BLUE}${raw_count}${NC} WAF events..."
    echo ""
    parse_logs

    local safe_count=0 suspicious_count=0 attack_count=0

    # Sort by hits descending
    local sorted_keys
    sorted_keys=$(for key in "${!LOG_RULE_HITS[@]}"; do
        echo "${LOG_RULE_HITS[$key]} $key"
    done | sort -rn)

    echo -e "${BOLD}  Classification Results${NC}"
    echo -e "  ${DIM}  Verdict     Hits  IPs  Rule  Description${NC}"
    echo ""

    while IFS=' ' read -r hits key; do
        [[ -z "$key" ]] && continue
        IFS='|' read -r id zone uri var_name <<< "$key"

        local result
        result=$(classify_rule "$key")
        local verdict="${result%%|*}"
        local reason="${result#*|}"

        local ip_list="${LOG_RULE_IPS[$key]:-}"
        local ip_count=0
        if [[ -n "$ip_list" ]]; then
            ip_count=$(echo "$ip_list" | tr ' ' '\n' | grep -c . || true)
        fi

        local desc
        desc=$(get_rule_description "$id")
        local color=""

        case "$verdict" in
            SAFE)
                color="$GREEN"
                safe_count=$((safe_count + 1))
                ;;
            SUSPICIOUS)
                color="$YELLOW"
                suspicious_count=$((suspicious_count + 1))
                ;;
            ATTACK)
                color="$RED"
                attack_count=$((attack_count + 1))
                ;;
        esac

        printf "  %b%-10s%b  %5d  %3d  %-5s %s\n" \
            "$color" "$verdict" "$NC" "$hits" "$ip_count" "$id" "$desc"
        echo -e "  ${DIM}  -> ${reason}${NC}"
        echo ""
    done <<< "$sorted_keys"

    # Summary
    echo -e "${BOLD}  Summary${NC}"
    echo -e "  Total events:     ${BLUE}${LOG_TOTAL_EVENTS}${NC}"
    echo -e "  Unique IPs:       ${BLUE}${LOG_UNIQUE_IPS}${NC}"
    echo -e "  Rule combinations: ${BLUE}${#LOG_RULE_HITS[@]}${NC}"
    echo ""
    echo -e "  ${GREEN}SAFE (auto-whitelist OK):  ${safe_count}${NC}"
    echo -e "  ${YELLOW}SUSPICIOUS (needs review): ${suspicious_count}${NC}"
    echo -e "  ${RED}ATTACK (block):            ${attack_count}${NC}"
    echo ""

    if [[ $safe_count -gt 0 ]]; then
        echo -e "  Run ${CYAN}sudo naxsi-ai-agent auto-whitelist${NC} to apply safe rules."
    fi
    if [[ $suspicious_count -gt 0 ]]; then
        echo -e "  Run ${CYAN}sudo naxsi-ai-agent investigate <ip>${NC} to check suspicious traffic."
    fi
    echo ""

    log_agent "INFO" "Analysis complete: safe=$safe_count suspicious=$suspicious_count attack=$attack_count events=$LOG_TOTAL_EVENTS"
}

# --- Auto-whitelist: apply only SAFE rules ---
cmd_auto_whitelist() {
    echo ""
    echo -e "${BOLD}=== AI Security Agent — Auto-Whitelist ===${NC}"
    echo ""

    if [[ ! -f "$ERROR_LOG" ]]; then
        echo -e "${RED}Error log not found: ${ERROR_LOG}${NC}"
        return 1
    fi

    local raw_count
    raw_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)
    if [[ "$raw_count" -eq 0 ]]; then
        echo -e "${GREEN}No events to process.${NC}"
        return
    fi

    echo -e "Analyzing ${BLUE}${raw_count}${NC} events..."
    parse_logs

    local -a safe_keys=()
    local -a safe_reasons=()

    local sorted_keys
    sorted_keys=$(for key in "${!LOG_RULE_HITS[@]}"; do
        echo "${LOG_RULE_HITS[$key]} $key"
    done | sort -rn)

    while IFS=' ' read -r hits key; do
        [[ -z "$key" ]] && continue

        local result
        result=$(classify_rule "$key")
        local verdict="${result%%|*}"
        local reason="${result#*|}"

        if [[ "$verdict" == "SAFE" ]]; then
            # Double-check: is this rule ID in the never-whitelist list?
            IFS='|' read -r id _ _ _ <<< "$key"
            local blocked=false
            for blocked_id in "${NEVER_AUTO_WHITELIST[@]}"; do
                if [[ "$id" == "$blocked_id" ]]; then
                    blocked=true
                    break
                fi
            done
            if [[ "$blocked" == "false" ]]; then
                safe_keys+=("$key")
                safe_reasons+=("$reason")
            fi
        fi
    done <<< "$sorted_keys"

    if [[ ${#safe_keys[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No rules qualified for auto-whitelisting.${NC}"
        echo -e "Rules must meet these thresholds:"
        echo -e "  Minimum hits:       ${BLUE}${MIN_HITS_AUTO_WHITELIST}${NC}"
        echo -e "  Minimum unique IPs: ${BLUE}${MIN_IPS_AUTO_WHITELIST}${NC}"
        echo -e "  Risk level:         ${GREEN}low${NC} or ${YELLOW}medium${NC} (not high/critical)"
        echo ""
        return
    fi

    echo ""
    echo -e "Found ${GREEN}${#safe_keys[@]}${NC} rules that are safe to auto-whitelist:"
    echo ""

    for i in "${!safe_keys[@]}"; do
        local key="${safe_keys[$i]}"
        local reason="${safe_reasons[$i]}"
        IFS='|' read -r id zone uri var_name <<< "$key"
        local hits="${LOG_RULE_HITS[$key]}"
        local mz
        mz=$(build_matchzone "$zone" "$uri" "$var_name")

        printf "  ${GREEN}[%d]${NC} wl:%s mz:%s  ${DIM}(%d hits)${NC}\n" \
            $((i + 1)) "$id" "$mz" "$hits"
        echo -e "      ${DIM}${reason}${NC}"
        echo ""
    done

    echo -ne "Apply these ${GREEN}${#safe_keys[@]}${NC} rules? [y/N] "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}Cancelled. No changes made.${NC}"
        return
    fi

    backup_file "$WHITELIST_FILE"

    echo "" >> "$WHITELIST_FILE"
    echo "# Auto-whitelisted by AI agent $(date '+%Y-%m-%d %H:%M:%S')" >> "$WHITELIST_FILE"

    for i in "${!safe_keys[@]}"; do
        local key="${safe_keys[$i]}"
        local reason="${safe_reasons[$i]}"
        IFS='|' read -r id zone uri var_name <<< "$key"
        local hits="${LOG_RULE_HITS[$key]}"
        local mz
        mz=$(build_matchzone "$zone" "$uri" "$var_name")
        local desc
        desc=$(get_rule_description "$id")

        echo "# AI-agent: $reason" >> "$WHITELIST_FILE"
        echo "BasicRule wl:${id} \"mz:${mz}\";" >> "$WHITELIST_FILE"
        log_decision "AUTO_WHITELIST" "$id" "$reason"
    done

    if reload_nginx; then
        echo ""
        echo -e "${GREEN}Applied ${#safe_keys[@]} whitelist rules. Nginx reloaded.${NC}"
    else
        echo -e "${RED}Nginx config test failed. Check the rules manually.${NC}"
    fi
    echo ""
}

# --- Investigate: why is an IP or URI being blocked? ---
cmd_investigate() {
    local target="${1:-}"

    if [[ -z "$target" ]]; then
        echo -e "${RED}Usage: naxsi-ai-agent investigate <ip-or-uri>${NC}"
        return 1
    fi

    echo ""
    echo -e "${BOLD}=== AI Security Agent — Investigation ===${NC}"
    echo -e "  Target: ${CYAN}${target}${NC}"
    echo ""

    if [[ ! -f "$ERROR_LOG" ]]; then
        echo -e "${RED}Error log not found.${NC}"
        return 1
    fi

    # Determine if target is an IP or URI
    local is_ip=false
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        is_ip=true
    fi

    # Count matching events
    local match_count
    match_count=$(grep -c "NAXSI_FMT.*${target}" "$ERROR_LOG" 2>/dev/null || true)

    if [[ "$match_count" -eq 0 ]]; then
        echo -e "${GREEN}No WAF events found for '${target}'.${NC}"
        if [[ "$is_ip" == "true" ]]; then
            echo ""
            echo -e "${BOLD}  Agent Assessment:${NC}"
            echo -e "  This IP has no recorded WAF blocks. Possible causes:"
            echo -e "  1. The IP was never blocked (check access.log for 200 responses)"
            echo -e "  2. The error log was rotated since the block occurred"
            echo -e "  3. The block happened at network level (firewall/iptables), not WAF"
            echo ""
            # Check access log
            if [[ -f "$ACCESS_LOG" ]]; then
                local access_count
                access_count=$(grep -c "$target" "$ACCESS_LOG" 2>/dev/null || true)
                if [[ "$access_count" -gt 0 ]]; then
                    echo -e "  Found ${BLUE}${access_count}${NC} entries in access.log for this IP."
                    echo -e "  Recent requests:"
                    grep "$target" "$ACCESS_LOG" | tail -5 | while IFS= read -r line; do
                        echo -e "    ${DIM}${line}${NC}"
                    done
                else
                    echo -e "  ${YELLOW}No entries in access.log either — IP may not have reached this server.${NC}"
                fi
            fi
        fi
        echo ""
        return
    fi

    echo -e "Found ${BLUE}${match_count}${NC} WAF events matching '${target}'. Analyzing..."
    echo ""

    # Parse only matching events
    local -A inv_rules=()    # "id|zone|uri|var" -> hits
    local -A inv_ips=()      # ip -> hits
    local -A inv_uris=()     # uri -> hits

    while IFS= read -r line; do
        local uri="" ip=""
        uri=$(echo "$line" | grep -oP 'uri=[^&,]+' | head -1 | cut -d= -f2 || true)
        ip=$(echo "$line" | grep -oP 'ip=[^&,]+' | head -1 | cut -d= -f2 || true)

        [[ -n "$ip" ]] && inv_ips[$ip]=$(( ${inv_ips[$ip]:-0} + 1 ))
        [[ -n "$uri" ]] && inv_uris[$uri]=$(( ${inv_uris[$uri]:-0} + 1 ))

        local idx=0
        while true; do
            local zone id var_name
            zone=$(echo "$line" | grep -oP "zone${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            id=$(echo "$line" | grep -oP "(?<=[^_])id${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            var_name=$(echo "$line" | grep -oP "var_name${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)

            [[ -z "$zone" || -z "$id" ]] && break

            local key="${id}|${zone}|${uri}|${var_name}"
            inv_rules[$key]=$(( ${inv_rules[$key]:-0} + 1 ))

            idx=$((idx + 1))
        done
    done < <(grep "NAXSI_FMT.*${target}" "$ERROR_LOG")

    # Display findings
    echo -e "${BOLD}  Triggered Rules${NC}"
    echo -e "  ${DIM}  Hits  Rule  Risk      Description${NC}"

    local sorted_rules
    sorted_rules=$(for key in "${!inv_rules[@]}"; do
        echo "${inv_rules[$key]} $key"
    done | sort -rn)

    local has_critical=false
    local has_high=false
    local all_low=true

    while IFS=' ' read -r hits key; do
        [[ -z "$key" ]] && continue
        IFS='|' read -r id zone uri var_name <<< "$key"
        local desc
        desc=$(get_rule_description "$id")
        local risk
        risk=$(get_rule_risk "$id")
        local risk_color="$NC"

        case "$risk" in
            low)      risk_color="$GREEN" ;;
            medium)   risk_color="$YELLOW"; all_low=false ;;
            high)     risk_color="$RED"; has_high=true; all_low=false ;;
            critical) risk_color="$RED"; has_critical=true; all_low=false ;;
        esac

        printf "  %5d  %-5s %b%-8s%b  %s\n" "$hits" "$id" "$risk_color" "$risk" "$NC" "$desc"
        if [[ -n "$var_name" ]]; then
            echo -e "         ${DIM}zone: ${zone}  var: ${var_name}${uri:+  uri: $uri}${NC}"
        fi
    done <<< "$sorted_rules"
    echo ""

    if [[ "$is_ip" == "true" ]]; then
        echo -e "${BOLD}  URIs accessed by this IP${NC}"
        for uri in "${!inv_uris[@]}"; do
            printf "  %5d  %s\n" "${inv_uris[$uri]}" "$uri"
        done
        echo ""
    else
        echo -e "${BOLD}  IPs triggering rules on this URI${NC}"
        for ip in "${!inv_ips[@]}"; do
            printf "  %5d  %s\n" "${inv_ips[$ip]}" "$ip"
        done
        echo ""
    fi

    # Agent's assessment
    echo -e "${BOLD}  Agent Assessment${NC}"
    echo ""

    if [[ "$has_critical" == "true" ]]; then
        echo -e "  ${RED}DENY — Critical security rules triggered.${NC}"
        echo -e "  This traffic pattern matches known attack signatures (SQL injection,"
        echo -e "  path traversal, or command execution probes). These rules have very"
        echo -e "  low false-positive rates."
        echo ""
        echo -e "  ${BOLD}Recommendation:${NC} Do NOT whitelist. If the user claims this is"
        echo -e "  legitimate, they should modify their application to avoid sending"
        echo -e "  payloads that look like attacks."
    elif [[ "$has_high" == "true" ]]; then
        echo -e "  ${YELLOW}REVIEW — High-risk rules triggered.${NC}"
        echo -e "  Some triggered rules indicate potentially dangerous payloads."
        echo -e "  This could be a sophisticated attack or an unusual but legitimate"
        echo -e "  application pattern."
        echo ""
        echo -e "  ${BOLD}Recommendation:${NC} Manually inspect the actual request payloads"
        echo -e "  before whitelisting. Use learning mode to capture full request details."
    elif [[ "$all_low" == "true" && ${#inv_ips[@]} -gt 5 ]]; then
        echo -e "  ${GREEN}APPROVE — Low-risk rules, diverse sources.${NC}"
        echo -e "  All triggered rules are low-risk (common false positives like quotes,"
        echo -e "  brackets, or equal signs in form data). Traffic comes from ${BLUE}${#inv_ips[@]}${NC}"
        echo -e "  different IPs, indicating normal user behavior."
        echo ""
        echo -e "  ${BOLD}Recommendation:${NC} Safe to whitelist. Run:"
        echo -e "  ${CYAN}sudo naxsi-ai-agent auto-whitelist${NC}"
    else
        echo -e "  ${YELLOW}INVESTIGATE FURTHER — Mixed signals.${NC}"
        echo -e "  The traffic pattern is ambiguous. Triggered rules are medium-risk"
        echo -e "  and there is limited IP diversity (${#inv_ips[@]} IPs)."
        echo ""
        echo -e "  ${BOLD}Recommendation:${NC} Enable learning mode to gather more data:"
        echo -e "  ${CYAN}sudo naxsi-manager learn-on${NC}"
    fi
    echo ""

    log_agent "INVESTIGATE" "target=$target events=$match_count rules=${#inv_rules[@]} critical=$has_critical high=$has_high"
}

# --- Request: user asks for access, agent decides ---
cmd_request() {
    local req_ip="${1:-}"
    local req_uri="${2:-}"

    if [[ -z "$req_ip" ]]; then
        echo -e "${RED}Usage: naxsi-ai-agent request <ip> [uri]${NC}"
        echo -e "Example: naxsi-ai-agent request 10.0.0.5 /api/login"
        return 1
    fi

    echo ""
    echo -e "${BOLD}=== AI Security Agent — Access Request Review ===${NC}"
    echo ""
    echo -e "  Requester IP: ${CYAN}${req_ip}${NC}"
    [[ -n "$req_uri" ]] && echo -e "  Requested URI: ${CYAN}${req_uri}${NC}"
    echo ""

    # Parse logs for this IP
    local match_pattern="NAXSI_FMT.*ip=${req_ip}[&,]"
    if [[ -n "$req_uri" ]]; then
        match_pattern="NAXSI_FMT.*ip=${req_ip}.*uri=${req_uri}"
    fi

    local match_count
    match_count=$(grep -cP "$match_pattern" "$ERROR_LOG" 2>/dev/null || true)

    if [[ "$match_count" -eq 0 ]]; then
        echo -e "${GREEN}APPROVED — No WAF blocks found for this IP${req_uri:+ on $req_uri}.${NC}"
        echo ""
        echo -e "  ${BOLD}Agent Decision:${NC} APPROVE"
        echo -e "  ${BOLD}Reason:${NC} No security events recorded. The connection issue"
        echo -e "  is not caused by the WAF. Check:"
        echo -e "    - Network connectivity (firewall, routing)"
        echo -e "    - DNS resolution"
        echo -e "    - Backend server availability"
        echo -e "    - TLS certificate validity"
        echo ""
        log_decision "APPROVE" "n/a" "No WAF events for IP $req_ip${req_uri:+ uri=$req_uri}"
        return
    fi

    echo -e "Found ${BLUE}${match_count}${NC} WAF blocks. Analyzing..."
    echo ""

    # Collect triggered rules
    local -A req_rules=()
    local has_critical=false
    local has_high=false

    while IFS= read -r line; do
        local idx=0
        while true; do
            local zone id var_name
            zone=$(echo "$line" | grep -oP "zone${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            id=$(echo "$line" | grep -oP "(?<=[^_])id${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            var_name=$(echo "$line" | grep -oP "var_name${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)

            [[ -z "$zone" || -z "$id" ]] && break

            req_rules[$id]=$(( ${req_rules[$id]:-0} + 1 ))
            local risk
            risk=$(get_rule_risk "$id")
            [[ "$risk" == "critical" ]] && has_critical=true
            [[ "$risk" == "high" ]] && has_high=true

            idx=$((idx + 1))
        done
    done < <(grep -P "$match_pattern" "$ERROR_LOG")

    echo -e "  ${BOLD}Rules triggered by this IP:${NC}"
    for id in "${!req_rules[@]}"; do
        local desc
        desc=$(get_rule_description "$id")
        local risk
        risk=$(get_rule_risk "$id")
        local risk_color="$NC"
        case "$risk" in
            low) risk_color="$GREEN" ;;
            medium) risk_color="$YELLOW" ;;
            high|critical) risk_color="$RED" ;;
        esac
        printf "    %-5s  %b%-8s%b  %s  (%d times)\n" "$id" "$risk_color" "$risk" "$NC" "$desc" "${req_rules[$id]}"
    done
    echo ""

    # Parse full logs to check if other IPs trigger the same rules
    parse_logs

    echo -e "  ${BOLD}Agent Decision:${NC}"
    echo ""

    if [[ "$has_critical" == "true" ]]; then
        echo -e "  ${RED}DENIED${NC}"
        echo ""
        echo -e "  ${BOLD}Reason:${NC} This IP triggered critical security rules that indicate"
        echo -e "  active exploitation attempts (SQL injection, path traversal, or"
        echo -e "  command execution). These are NOT false positives."
        echo ""
        echo -e "  ${BOLD}What the user should do:${NC}"
        echo -e "  - If using a legitimate application: modify the app to avoid sending"
        echo -e "    payloads that contain SQL syntax, path traversal sequences, or"
        echo -e "    system command patterns."
        echo -e "  - If this is a security scanner: stop scanning or get authorization."
        echo ""
        log_decision "DENY" "$(echo "${!req_rules[@]}" | tr ' ' ',')" "Critical rules triggered by IP $req_ip — likely attack"

    elif [[ "$has_high" == "true" ]]; then
        echo -e "  ${YELLOW}DENIED (pending review)${NC}"
        echo ""
        echo -e "  ${BOLD}Reason:${NC} High-risk rules were triggered. While these can"
        echo -e "  occasionally be false positives, auto-whitelisting is too risky."
        echo ""
        echo -e "  ${BOLD}What happens next:${NC}"
        echo -e "  The security team will review this request. If the traffic is"
        echo -e "  confirmed legitimate, specific whitelist rules will be added for"
        echo -e "  the affected URIs only (not a global bypass)."
        echo ""
        log_decision "DENY_PENDING_REVIEW" "$(echo "${!req_rules[@]}" | tr ' ' ',')" "High-risk rules triggered by IP $req_ip — requires manual review"

    else
        # Check if many other IPs also trigger these rules (legitimacy signal)
        local widespread=true
        for id in "${!req_rules[@]}"; do
            local total_hits="${LOG_ID_TOTAL[$id]:-0}"
            if [[ $total_hits -lt $MIN_HITS_AUTO_WHITELIST ]]; then
                widespread=false
            fi
        done

        if [[ "$widespread" == "true" ]]; then
            echo -e "  ${GREEN}APPROVED — whitelist rules will be generated${NC}"
            echo ""
            echo -e "  ${BOLD}Reason:${NC} The rules triggered by this IP are low/medium risk"
            echo -e "  AND are widely triggered by many other IPs across the site."
            echo -e "  This confirms a false-positive pattern. Whitelist rules will be"
            echo -e "  scoped to specific URIs and parameters (not global bypasses)."
            echo ""
            echo -e "  Run ${CYAN}sudo naxsi-ai-agent auto-whitelist${NC} to apply."
            echo ""
            log_decision "APPROVE" "$(echo "${!req_rules[@]}" | tr ' ' ',')" "Low-risk rules widely triggered — confirmed false positive for IP $req_ip"
        else
            echo -e "  ${YELLOW}NEEDS MORE DATA${NC}"
            echo ""
            echo -e "  ${BOLD}Reason:${NC} The rules are low/medium risk but there's not enough"
            echo -e "  traffic data to confirm this as a widespread false positive."
            echo -e "  The agent cannot safely auto-whitelist with current data."
            echo ""
            echo -e "  ${BOLD}Recommendation:${NC} Enable learning mode to collect more data:"
            echo -e "  ${CYAN}sudo naxsi-manager learn-on${NC}"
            echo -e "  Then wait for normal traffic before re-analyzing."
            echo ""
            log_decision "DEFER" "$(echo "${!req_rules[@]}" | tr ' ' ',')" "Insufficient data for IP $req_ip — need more traffic in learning mode"
        fi
    fi
}

# --- Report: generate a security summary ---
cmd_report() {
    echo ""
    echo -e "${BOLD}=== AI Security Agent — Security Report ===${NC}"
    echo -e "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # WAF status
    if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        echo -e "  WAF Mode:       ${YELLOW}LEARNING${NC} (logging only)"
    else
        echo -e "  WAF Mode:       ${GREEN}BLOCKING${NC} (active protection)"
    fi

    local wl_count=0
    [[ -f "$WHITELIST_FILE" ]] && wl_count=$(grep -cP '^\s*BasicRule' "$WHITELIST_FILE" 2>/dev/null || true)
    echo -e "  Whitelist Rules: ${BLUE}${wl_count}${NC}"

    local event_count=0
    [[ -f "$ERROR_LOG" ]] && event_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)
    echo -e "  WAF Events:      ${BLUE}${event_count}${NC}"

    # Decision history
    local total_decisions=0 approvals=0 denials=0
    if [[ -f "$DECISIONS_LOG" ]]; then
        total_decisions=$(wc -l < "$DECISIONS_LOG" || true)
        approvals=$(grep -c 'action=APPROVE\|action=AUTO_WHITELIST' "$DECISIONS_LOG" 2>/dev/null || true)
        denials=$(grep -c 'action=DENY' "$DECISIONS_LOG" 2>/dev/null || true)
    fi
    echo ""
    echo -e "  ${BOLD}Decision History${NC}"
    echo -e "  Total decisions:  ${BLUE}${total_decisions}${NC}"
    echo -e "  Approved:         ${GREEN}${approvals}${NC}"
    echo -e "  Denied:           ${RED}${denials}${NC}"

    if [[ $event_count -gt 0 ]]; then
        echo ""
        parse_logs

        echo -e ""
        echo -e "  ${BOLD}Top 5 Blocked IPs${NC}"
        local sorted_ips
        sorted_ips=$(for ip in "${!LOG_IP_TOTAL[@]}"; do
            echo "${LOG_IP_TOTAL[$ip]} $ip"
        done | sort -rn | head -5)
        while IFS=' ' read -r hits ip; do
            [[ -z "$ip" ]] && continue
            printf "    %6d events  %s\n" "$hits" "$ip"
        done <<< "$sorted_ips"

        echo ""
        echo -e "  ${BOLD}Top 5 Triggered Rules${NC}"
        local sorted_ids
        sorted_ids=$(for id in "${!LOG_ID_TOTAL[@]}"; do
            echo "${LOG_ID_TOTAL[$id]} $id"
        done | sort -rn | head -5)
        while IFS=' ' read -r hits id; do
            [[ -z "$id" ]] && continue
            local desc
            desc=$(get_rule_description "$id")
            local risk
            risk=$(get_rule_risk "$id")
            printf "    %6d events  %-5s %-8s  %s\n" "$hits" "$id" "($risk)" "$desc"
        done <<< "$sorted_ids"
    fi

    echo ""
    echo -e "  ${BOLD}Agent Log:${NC}      ${DIM}${AGENT_LOG}${NC}"
    echo -e "  ${BOLD}Decisions Log:${NC}  ${DIM}${DECISIONS_LOG}${NC}"
    echo ""

    # Save report
    local report_file="${REPORT_DIR}/report_$(date '+%Y%m%d_%H%M%S').txt"
    log_agent "INFO" "Security report generated: $report_file"
}

# --- Daemon: continuous monitoring ---
cmd_daemon() {
    echo -e "${BOLD}Naxsi AI Security Agent — Daemon Mode${NC}"
    echo -e "Checking every ${DAEMON_INTERVAL}s. Press Ctrl+C to stop."
    echo ""

    log_agent "INFO" "Daemon started (interval=${DAEMON_INTERVAL}s)"

    # Track last processed line count to avoid re-processing
    local last_line_count=0
    if [[ -f "${AGENT_STATE}/last_line_count" ]]; then
        last_line_count=$(cat "${AGENT_STATE}/last_line_count")
    fi

    while true; do
        local current_count=0
        if [[ -f "$ERROR_LOG" ]]; then
            current_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)
        fi

        if [[ $current_count -gt $last_line_count ]]; then
            local new_events=$((current_count - last_line_count))
            log_agent "INFO" "Daemon: $new_events new events detected (total: $current_count)"

            # Run analysis
            parse_logs

            local auto_count=0
            for key in "${!LOG_RULE_HITS[@]}"; do
                local result
                result=$(classify_rule "$key")
                local verdict="${result%%|*}"
                [[ "$verdict" == "SAFE" ]] && auto_count=$((auto_count + 1))
            done

            if [[ $auto_count -gt 0 ]]; then
                log_agent "INFO" "Daemon: $auto_count rules qualify for auto-whitelist"
                echo "[$(date '+%H:%M:%S')] $new_events new events, $auto_count auto-whitelist candidates"
            fi

            last_line_count=$current_count
            echo "$last_line_count" > "${AGENT_STATE}/last_line_count"
        fi

        sleep "$DAEMON_INTERVAL"
    done
}

# --- Policy: show current security policy ---
cmd_policy() {
    echo ""
    echo -e "${BOLD}=== AI Security Agent — Security Policy ===${NC}"
    echo ""
    echo -e "  ${BOLD}Auto-Whitelist Thresholds${NC}"
    echo -e "  Minimum hits required:           ${BLUE}${MIN_HITS_AUTO_WHITELIST}${NC}"
    echo -e "  Minimum unique IPs:              ${BLUE}${MIN_IPS_AUTO_WHITELIST}${NC}"
    echo -e "  Single-IP suspicion threshold:   ${BLUE}${SINGLE_IP_SUSPICION_THRESHOLD}${NC} hits"
    echo -e "  Single-IP ratio threshold:       ${BLUE}${SINGLE_IP_RATIO_THRESHOLD}%${NC}"
    echo ""
    echo -e "  ${BOLD}Never Auto-Whitelist (always require human review)${NC}"
    for id in "${NEVER_AUTO_WHITELIST[@]}"; do
        local desc
        desc=$(get_rule_description "$id")
        echo -e "    Rule ${RED}${id}${NC}: ${desc}"
    done
    echo ""
    echo -e "  ${BOLD}Rule Risk Classification${NC}"
    echo -e "    ${GREEN}low${NC}       Common false positives (quotes, brackets, commas)"
    echo -e "              -> Auto-whitelist OK when thresholds met"
    echo -e "    ${YELLOW}medium${NC}    Context-dependent (SQL keywords, encoding)"
    echo -e "              -> Auto-whitelist OK when thresholds met"
    echo -e "    ${RED}high${NC}      Rarely false positive (hex encoding, file uploads)"
    echo -e "              -> Requires high diversity + manual confirmation"
    echo -e "    ${RED}critical${NC}  Almost always attack (libinjection, path probes)"
    echo -e "              -> NEVER auto-whitelist"
    echo ""
    echo -e "  ${BOLD}Decision Framework${NC}"
    echo -e "    SAFE       = Low/medium risk + high hits + many IPs -> auto-whitelist"
    echo -e "    SUSPICIOUS = Insufficient data or single-IP dominance -> defer"
    echo -e "    ATTACK     = Critical/high risk + low diversity -> block"
    echo ""
    echo -e "  Edit thresholds in: ${CYAN}$(readlink -f "$0")${NC}"
    echo ""
}

# ============================================================
# Main
# ============================================================
main() {
    check_root
    ensure_dirs

    local cmd="${1:-}"
    shift 2>/dev/null || true

    case "$cmd" in
        analyze)         cmd_analyze ;;
        auto-whitelist)  cmd_auto_whitelist ;;
        investigate)     cmd_investigate "$@" ;;
        request)         cmd_request "$@" ;;
        report)          cmd_report ;;
        daemon)          cmd_daemon ;;
        policy)          cmd_policy ;;
        help|--help|-h)
            echo "Usage: sudo naxsi-ai-agent <command> [args]"
            echo ""
            echo "The AI Security Agent analyzes WAF logs and makes autonomous"
            echo "security decisions. It acts as a security engineer — it does"
            echo "NOT blindly follow user requests."
            echo ""
            echo "Commands:"
            echo "  analyze               Analyze logs, classify each rule trigger"
            echo "  auto-whitelist        Auto-apply rules classified as SAFE"
            echo "  investigate <target>  Investigate an IP or URI (why blocked?)"
            echo "  request <ip> [uri]    User requests access — agent decides"
            echo "  report                Generate security summary report"
            echo "  daemon                Run continuously (every ${DAEMON_INTERVAL}s)"
            echo "  policy                Show current security policy and thresholds"
            echo "  help                  Show this help"
            echo ""
            echo "Security Policy:"
            echo "  Auto-whitelist requires: >=${MIN_HITS_AUTO_WHITELIST} hits AND >=${MIN_IPS_AUTO_WHITELIST} unique IPs"
            echo "  Critical rules (${NEVER_AUTO_WHITELIST[*]}) are NEVER auto-whitelisted"
            echo ""
            echo "Logs:"
            echo "  Agent log:      ${AGENT_LOG}"
            echo "  Decisions log:  ${DECISIONS_LOG}"
            ;;
        "")
            echo "Usage: sudo naxsi-ai-agent <command>"
            echo "Run 'naxsi-ai-agent help' for details."
            ;;
        *)
            echo "Unknown command: $cmd"
            echo "Run 'naxsi-ai-agent help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
