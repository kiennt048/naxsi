#!/bin/bash
#
# naxsi-manager.sh — Naxsi WAF Learning Mode & Whitelist Manager
#
# Interactive tool to:
#   1. Enable / disable learning mode
#   2. Parse Nginx error logs for Naxsi learning events
#   3. Generate whitelist rules from learning data
#   4. Review, edit, accept/reject individual rules
#   5. Apply approved rules and reload Nginx
#
# Usage:
#   sudo bash naxsi-manager.sh              Interactive menu
#   sudo bash naxsi-manager.sh status       Show current mode & stats
#   sudo bash naxsi-manager.sh learn-on     Enable learning mode
#   sudo bash naxsi-manager.sh learn-off    Disable learning mode
#   sudo bash naxsi-manager.sh generate     Parse logs and generate rules
#   sudo bash naxsi-manager.sh show         Show current whitelist rules
#   sudo bash naxsi-manager.sh apply        Apply pending rules after review
#
set -euo pipefail

# ============================================================
# Configuration — adjust paths if needed
# ============================================================
NAXSI_RULES="/etc/nginx/naxsi.rules"
WHITELIST_FILE="/etc/nginx/naxsi_whitelist.rules"
PENDING_FILE="/etc/nginx/naxsi_whitelist_pending.rules"
ERROR_LOG="/var/log/nginx/error.log"
BACKUP_DIR="/etc/nginx/naxsi_backups"

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
# Rule ID -> Description map
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

# Score category descriptions
declare -A SCORE_DESC=(
    ['$SQL']="SQL Injection"
    ['$XSS']="Cross-Site Scripting"
    ['$RFI']="Remote File Inclusion"
    ['$TRAVERSAL']="Directory Traversal"
    ['$EVADE']="Evasion Technique"
    ['$UPLOAD']="File Upload"
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

ensure_files() {
    mkdir -p "$BACKUP_DIR"
    touch "$WHITELIST_FILE"
    chmod 644 "$WHITELIST_FILE"
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
        echo -e "${GREEN}Nginx reloaded successfully.${NC}"
    else
        echo -e "${RED}ERROR: Nginx config test failed! Changes NOT applied.${NC}"
        echo -e "${YELLOW}Run 'nginx -t' to see the error.${NC}"
        return 1
    fi
}

get_rule_description() {
    local id="$1"
    echo "${RULE_DESC[$id]:-unknown rule}"
}

get_score_description() {
    local score="$1"
    echo "${SCORE_DESC[$score]:-$score}"
}

# ============================================================
# Status
# ============================================================
cmd_status() {
    echo ""
    echo -e "${BOLD}=== Naxsi WAF Status ===${NC}"
    echo ""

    # Learning mode status
    if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        echo -e "  Learning Mode:  ${YELLOW}ENABLED${NC} (logging only, not blocking)"
    elif grep -qP '^\s*#\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        echo -e "  Learning Mode:  ${GREEN}DISABLED${NC} (actively blocking)"
    else
        echo -e "  Learning Mode:  ${DIM}not configured${NC}"
    fi

    # Nginx status
    if pidof nginx > /dev/null 2>&1; then
        echo -e "  Nginx:          ${GREEN}running${NC}"
    else
        echo -e "  Nginx:          ${RED}stopped${NC}"
    fi

    # Whitelist rules count
    local wl_count=0
    if [[ -f "$WHITELIST_FILE" ]]; then
        wl_count=$(grep -cP '^\s*BasicRule' "$WHITELIST_FILE" 2>/dev/null || true)
    fi
    echo -e "  Whitelist Rules: ${BLUE}${wl_count}${NC}  (${WHITELIST_FILE})"

    # Pending rules count
    local pending_count=0
    if [[ -f "$PENDING_FILE" ]]; then
        pending_count=$(grep -cP '^\s*BasicRule' "$PENDING_FILE" 2>/dev/null || true)
    fi
    if [[ $pending_count -gt 0 ]]; then
        echo -e "  Pending Rules:  ${YELLOW}${pending_count}${NC}  (awaiting review)"
    fi

    # Learning events in log
    local event_count=0
    if [[ -f "$ERROR_LOG" ]]; then
        event_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)
    fi
    echo -e "  Log Events:     ${BLUE}${event_count}${NC}  (in ${ERROR_LOG})"

    echo ""
}

# ============================================================
# Learning mode toggle
# ============================================================
cmd_learn_on() {
    backup_file "$NAXSI_RULES"

    if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        echo -e "${YELLOW}Learning mode is already enabled.${NC}"
        return
    fi

    # Uncomment LearningMode line
    if grep -qP '^\s*#\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        sed -i 's/^\(\s*\)#\s*LearningMode;/\1LearningMode;/' "$NAXSI_RULES"
    else
        # Add LearningMode after SecRulesEnabled
        sed -i '/SecRulesEnabled;/a\        LearningMode;' "$NAXSI_RULES"
    fi

    reload_nginx
    echo ""
    echo -e "${GREEN}Learning mode ENABLED.${NC}"
    echo -e "Naxsi will ${YELLOW}log${NC} but ${YELLOW}not block${NC} requests."
    echo -e "Send normal traffic to your site, then run: ${CYAN}naxsi-manager generate${NC}"
    echo ""
}

cmd_learn_off() {
    backup_file "$NAXSI_RULES"

    if ! grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
        echo -e "${YELLOW}Learning mode is already disabled.${NC}"
        return
    fi

    # Comment out LearningMode line
    sed -i 's/^\(\s*\)LearningMode;/\1#LearningMode;/' "$NAXSI_RULES"

    reload_nginx
    echo ""
    echo -e "${GREEN}Learning mode DISABLED.${NC}"
    echo -e "Naxsi is now ${RED}actively blocking${NC} malicious requests."
    echo ""
}

# ============================================================
# Parse logs and generate whitelist rules
# ============================================================
cmd_generate() {
    echo ""
    echo -e "${BOLD}=== Generating Whitelist Rules from Learning Data ===${NC}"
    echo ""

    if [[ ! -f "$ERROR_LOG" ]]; then
        echo -e "${RED}Error log not found: ${ERROR_LOG}${NC}"
        return 1
    fi

    local event_count
    event_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)

    if [[ "$event_count" -eq 0 ]]; then
        echo -e "${YELLOW}No Naxsi learning events found in ${ERROR_LOG}.${NC}"
        echo "Make sure learning mode is enabled and send some traffic."
        return
    fi

    echo -e "Found ${BLUE}${event_count}${NC} learning events. Parsing..."
    echo ""

    # Parse NAXSI_FMT lines and extract unique (id, zone, uri, var_name) tuples
    # NAXSI_FMT: ip=...&server=...&uri=/path&learning=1&...&zone0=ARGS&id0=1001&var_name0=q
    declare -A seen_rules
    local rules_generated=0

    while IFS= read -r line; do
        # Extract fields from NAXSI_FMT line
        local uri="" zones="" ids="" var_names=""

        # Get URI
        uri=$(echo "$line" | grep -oP 'uri=[^&,]+' | head -1 | cut -d= -f2)

        # Extract all zone/id/var_name groups (zone0, id0, var_name0, zone1, id1, ...)
        local idx=0
        while true; do
            local zone id var_name
            zone=$(echo "$line" | grep -oP "zone${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            id=$(echo "$line" | grep -oP "(?<=[^_])id${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)
            var_name=$(echo "$line" | grep -oP "var_name${idx}=[^&,]+" | head -1 | cut -d= -f2 || true)

            [[ -z "$zone" || -z "$id" ]] && break

            # Build a unique key
            local key="${id}|${zone}|${uri}|${var_name}"

            if [[ -z "${seen_rules[$key]+_}" ]]; then
                seen_rules[$key]=1
            fi

            idx=$((idx + 1))
        done
    done < <(grep 'NAXSI_FMT' "$ERROR_LOG")

    if [[ ${#seen_rules[@]} -eq 0 ]]; then
        echo -e "${YELLOW}Could not parse any rules from log events.${NC}"
        return
    fi

    # Generate whitelist rules from unique tuples
    : > "$PENDING_FILE"
    echo "# Naxsi whitelist rules — generated $(date '+%Y-%m-%d %H:%M:%S')" >> "$PENDING_FILE"
    echo "# Review each rule, then run: sudo naxsi-manager apply" >> "$PENDING_FILE"
    echo "#" >> "$PENDING_FILE"

    for key in "${!seen_rules[@]}"; do
        IFS='|' read -r id zone uri var_name <<< "$key"

        local mz=""
        local comment=""
        local desc
        desc=$(get_rule_description "$id")

        # Build match zone string
        # Naxsi zones: ARGS, BODY, URL, HEADERS, FILE_EXT
        # Whitelist mz format: $URL:/path|$ARGS_VAR:name or $URL:/path|ARGS etc.
        if [[ -n "$uri" && "$uri" != "/" && -n "$var_name" ]]; then
            # Specific URI + specific variable
            case "$zone" in
                ARGS)           mz="\$URL:${uri}|\$ARGS_VAR:${var_name}" ;;
                BODY)           mz="\$URL:${uri}|\$BODY_VAR:${var_name}" ;;
                HEADERS)        mz="\$URL:${uri}|\$HEADERS_VAR:${var_name}" ;;
                URL)            mz="\$URL:${uri}|URL" ;;
                FILE_EXT)       mz="\$URL:${uri}|FILE_EXT" ;;
                *)              mz="\$URL:${uri}|${zone}" ;;
            esac
        elif [[ -n "$uri" && "$uri" != "/" ]]; then
            # Specific URI, no variable name
            case "$zone" in
                ARGS)           mz="\$URL:${uri}|ARGS" ;;
                BODY)           mz="\$URL:${uri}|BODY" ;;
                URL)            mz="\$URL:${uri}|URL" ;;
                HEADERS)        mz="\$URL:${uri}|\$HEADERS_VAR:Cookie" ;;
                FILE_EXT)       mz="\$URL:${uri}|FILE_EXT" ;;
                *)              mz="\$URL:${uri}|${zone}" ;;
            esac
        elif [[ -n "$var_name" ]]; then
            # No specific URI, but has variable
            case "$zone" in
                ARGS)           mz="\$ARGS_VAR:${var_name}" ;;
                BODY)           mz="\$BODY_VAR:${var_name}" ;;
                HEADERS)        mz="\$HEADERS_VAR:${var_name}" ;;
                *)              mz="${zone}" ;;
            esac
        else
            # Generic zone whitelist
            mz="${zone}"
        fi

        comment="# wl rule ${id} (${desc}) on ${zone}"
        [[ -n "$uri" && "$uri" != "/" ]] && comment+=" for ${uri}"
        [[ -n "$var_name" ]] && comment+=" var=${var_name}"

        echo "${comment}" >> "$PENDING_FILE"
        echo "BasicRule wl:${id} \"mz:${mz}\";" >> "$PENDING_FILE"
        echo "" >> "$PENDING_FILE"

        rules_generated=$((rules_generated + 1))
    done

    chmod 644 "$PENDING_FILE"

    echo -e "${GREEN}Generated ${BLUE}${rules_generated}${GREEN} whitelist rules.${NC}"
    echo -e "Saved to: ${CYAN}${PENDING_FILE}${NC}"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. Review:  ${CYAN}sudo naxsi-manager show-pending${NC}"
    echo -e "  2. Edit:    ${CYAN}sudo nano ${PENDING_FILE}${NC}"
    echo -e "     Delete any lines you don't want to whitelist."
    echo -e "  3. Apply:   ${CYAN}sudo naxsi-manager apply${NC}"
    echo ""
}

# ============================================================
# Show rules
# ============================================================
cmd_show() {
    echo ""
    echo -e "${BOLD}=== Active Whitelist Rules ===${NC}"
    echo -e "${DIM}File: ${WHITELIST_FILE}${NC}"
    echo ""

    if [[ ! -f "$WHITELIST_FILE" ]] || ! grep -qP '^\s*BasicRule' "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "  ${DIM}(no active whitelist rules)${NC}"
        echo ""
        return
    fi

    local num=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            echo -e "  ${DIM}${line}${NC}"
        elif [[ "$line" =~ ^[[:space:]]*BasicRule ]]; then
            num=$((num + 1))
            # Extract rule ID for coloring
            local wl_id
            wl_id=$(echo "$line" | grep -oP 'wl:\K\d+' || true)
            local desc=""
            if [[ -n "$wl_id" ]]; then
                desc=$(get_rule_description "$wl_id")
            fi
            echo -e "  ${GREEN}[${num}]${NC} ${line}  ${DIM}# ${desc}${NC}"
        fi
    done < "$WHITELIST_FILE"

    echo ""
    echo -e "  Total: ${BLUE}${num}${NC} active rules"
    echo ""
}

cmd_show_pending() {
    echo ""
    echo -e "${BOLD}=== Pending Whitelist Rules (awaiting review) ===${NC}"
    echo -e "${DIM}File: ${PENDING_FILE}${NC}"
    echo ""

    if [[ ! -f "$PENDING_FILE" ]] || ! grep -qP '^\s*BasicRule' "$PENDING_FILE" 2>/dev/null; then
        echo -e "  ${DIM}(no pending rules — run 'generate' first)${NC}"
        echo ""
        return
    fi

    local num=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            echo -e "  ${DIM}${line}${NC}"
        elif [[ "$line" =~ ^[[:space:]]*BasicRule ]]; then
            num=$((num + 1))
            local wl_id
            wl_id=$(echo "$line" | grep -oP 'wl:\K\d+' || true)
            local desc=""
            if [[ -n "$wl_id" ]]; then
                desc=$(get_rule_description "$wl_id")
            fi
            echo -e "  ${YELLOW}[${num}]${NC} ${line}  ${DIM}# ${desc}${NC}"
        fi
    done < "$PENDING_FILE"

    echo ""
    echo -e "  Total: ${YELLOW}${num}${NC} pending rules"
    echo ""
    echo -e "  To edit:  ${CYAN}sudo nano ${PENDING_FILE}${NC}"
    echo -e "  To apply: ${CYAN}sudo naxsi-manager apply${NC}"
    echo ""
}

# ============================================================
# Interactive review of pending rules
# ============================================================
cmd_review() {
    echo ""
    echo -e "${BOLD}=== Interactive Rule Review ===${NC}"
    echo ""

    if [[ ! -f "$PENDING_FILE" ]] || ! grep -qP '^\s*BasicRule' "$PENDING_FILE" 2>/dev/null; then
        echo -e "${YELLOW}No pending rules to review. Run 'generate' first.${NC}"
        return
    fi

    local -a rules=()
    local -a comments=()
    local prev_comment=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*#.+wl\ rule ]]; then
            prev_comment="$line"
        elif [[ "$line" =~ ^[[:space:]]*BasicRule ]]; then
            rules+=("$line")
            comments+=("$prev_comment")
            prev_comment=""
        fi
    done < "$PENDING_FILE"

    local total=${#rules[@]}
    if [[ $total -eq 0 ]]; then
        echo -e "${YELLOW}No rules found in pending file.${NC}"
        return
    fi

    local -a approved=()
    local -a rejected=()

    echo -e "Reviewing ${BLUE}${total}${NC} rules. For each rule enter:"
    echo -e "  ${GREEN}y${NC} = accept   ${RED}n${NC} = reject   ${BLUE}e${NC} = edit   ${YELLOW}s${NC} = skip   ${DIM}q${NC} = quit"
    echo ""

    for i in "${!rules[@]}"; do
        local rule="${rules[$i]}"
        local comment="${comments[$i]}"
        local num=$((i + 1))

        local wl_id
        wl_id=$(echo "$rule" | grep -oP 'wl:\K\d+' || true)
        local mz
        mz=$(echo "$rule" | grep -oP 'mz:[^"]+' || true)
        local desc=""
        if [[ -n "$wl_id" ]]; then
            desc=$(get_rule_description "$wl_id")
        fi

        echo -e "${BOLD}--- Rule ${num}/${total} ---${NC}"
        [[ -n "$comment" ]] && echo -e "  ${DIM}${comment}${NC}"
        echo -e "  ${CYAN}${rule}${NC}"
        echo -e "  Rule ID: ${BLUE}${wl_id}${NC} (${desc})"
        echo -e "  Match:   ${mz}"
        echo ""

        while true; do
            echo -ne "  [y/n/e/s/q] > "
            read -r choice
            case "$choice" in
                y|Y)
                    approved+=("$comment" "$rule")
                    echo -e "  ${GREEN}Accepted.${NC}"
                    echo ""
                    break
                    ;;
                n|N)
                    rejected+=("$rule")
                    echo -e "  ${RED}Rejected.${NC}"
                    echo ""
                    break
                    ;;
                e|E)
                    echo -ne "  Enter modified rule: "
                    read -r edited_rule
                    if [[ -n "$edited_rule" ]]; then
                        approved+=("$comment" "$edited_rule")
                        echo -e "  ${GREEN}Accepted (edited).${NC}"
                    else
                        echo -e "  ${YELLOW}Empty input — skipped.${NC}"
                    fi
                    echo ""
                    break
                    ;;
                s|S)
                    echo -e "  ${YELLOW}Skipped.${NC}"
                    echo ""
                    break
                    ;;
                q|Q)
                    echo -e "  ${DIM}Quitting review.${NC}"
                    break 2
                    ;;
                *)
                    echo -e "  ${DIM}Enter y, n, e, s, or q.${NC}"
                    ;;
            esac
        done
    done

    echo ""
    echo -e "${GREEN}Accepted: ${#approved[@]}${NC} lines  |  ${RED}Rejected: ${#rejected[@]}${NC} rules"

    # Count only BasicRule lines in approved
    local approved_count=0
    for line in "${approved[@]}"; do
        [[ "$line" =~ ^[[:space:]]*BasicRule ]] && approved_count=$((approved_count + 1))
    done

    if [[ $approved_count -gt 0 ]]; then
        echo ""
        echo -ne "Apply ${GREEN}${approved_count}${NC} approved rules now? [y/N] "
        read -r confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            backup_file "$WHITELIST_FILE"
            echo "" >> "$WHITELIST_FILE"
            echo "# Approved $(date '+%Y-%m-%d %H:%M:%S')" >> "$WHITELIST_FILE"
            for line in "${approved[@]}"; do
                echo "$line" >> "$WHITELIST_FILE"
            done
            # Clear pending
            : > "$PENDING_FILE"
            reload_nginx
            echo -e "${GREEN}Rules applied and Nginx reloaded.${NC}"
        else
            # Save approved to pending for later
            : > "$PENDING_FILE"
            echo "# Reviewed $(date '+%Y-%m-%d %H:%M:%S') — approved rules pending apply" >> "$PENDING_FILE"
            for line in "${approved[@]}"; do
                echo "$line" >> "$PENDING_FILE"
            done
            echo -e "${YELLOW}Approved rules saved to pending file. Run 'apply' when ready.${NC}"
        fi
    fi
    echo ""
}

# ============================================================
# Apply pending rules
# ============================================================
cmd_apply() {
    echo ""
    if [[ ! -f "$PENDING_FILE" ]] || ! grep -qP '^\s*BasicRule' "$PENDING_FILE" 2>/dev/null; then
        echo -e "${YELLOW}No pending rules to apply.${NC}"
        return
    fi

    local pending_count
    pending_count=$(grep -cP '^\s*BasicRule' "$PENDING_FILE" || true)

    echo -e "About to apply ${BLUE}${pending_count}${NC} whitelist rules from:"
    echo -e "  ${CYAN}${PENDING_FILE}${NC}"
    echo ""

    # Show what will be applied
    grep -P '^\s*(BasicRule|#.+wl)' "$PENDING_FILE" | while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            echo -e "  ${DIM}${line}${NC}"
        else
            echo -e "  ${GREEN}${line}${NC}"
        fi
    done
    echo ""

    echo -ne "Apply these rules? [y/N] "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}Cancelled.${NC}"
        return
    fi

    backup_file "$WHITELIST_FILE"

    echo "" >> "$WHITELIST_FILE"
    echo "# Applied $(date '+%Y-%m-%d %H:%M:%S')" >> "$WHITELIST_FILE"
    cat "$PENDING_FILE" >> "$WHITELIST_FILE"

    : > "$PENDING_FILE"

    reload_nginx
    echo ""
    echo -e "${GREEN}${pending_count} whitelist rules applied. Nginx reloaded.${NC}"
    echo -e "Active whitelist: ${CYAN}${WHITELIST_FILE}${NC}"
    echo ""
}

# ============================================================
# Remove a whitelist rule
# ============================================================
cmd_remove() {
    if [[ ! -f "$WHITELIST_FILE" ]] || ! grep -qP '^\s*BasicRule' "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "${YELLOW}No active whitelist rules to remove.${NC}"
        return
    fi

    echo ""
    echo -e "${BOLD}=== Remove Whitelist Rule ===${NC}"
    echo ""

    local -a rules=()
    local num=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*BasicRule ]]; then
            num=$((num + 1))
            rules+=("$line")
            local wl_id
            wl_id=$(echo "$line" | grep -oP 'wl:\K\d+' || true)
            local desc=""
            if [[ -n "$wl_id" ]]; then
                desc=$(get_rule_description "$wl_id")
            fi
            echo -e "  ${GREEN}[${num}]${NC} ${line}  ${DIM}# ${desc}${NC}"
        fi
    done < "$WHITELIST_FILE"

    echo ""
    echo -ne "Enter rule number to remove (0 to cancel): "
    read -r choice

    if [[ "$choice" == "0" || -z "$choice" ]]; then
        echo -e "${DIM}Cancelled.${NC}"
        return
    fi

    if [[ "$choice" -lt 1 || "$choice" -gt "${#rules[@]}" ]] 2>/dev/null; then
        echo -e "${RED}Invalid selection.${NC}"
        return
    fi

    local rule_to_remove="${rules[$((choice - 1))]}"

    backup_file "$WHITELIST_FILE"

    # Escape special characters for sed
    local escaped_rule
    escaped_rule=$(printf '%s\n' "$rule_to_remove" | sed 's/[[\.*^$()+?{|]/\\&/g')
    sed -i "/${escaped_rule}/d" "$WHITELIST_FILE"

    reload_nginx
    echo -e "${GREEN}Rule removed and Nginx reloaded.${NC}"
    echo ""
}

# ============================================================
# Clear all log learning data
# ============================================================
cmd_clear_logs() {
    echo ""
    local count
    count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)

    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}No Naxsi events in error log.${NC}"
        return
    fi

    echo -ne "Clear ${BLUE}${count}${NC} Naxsi learning events from error log? [y/N] "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${DIM}Cancelled.${NC}"
        return
    fi

    backup_file "$ERROR_LOG"
    sed -i '/NAXSI_FMT/d' "$ERROR_LOG"
    echo -e "${GREEN}Cleared Naxsi events from error log.${NC}"
    echo ""
}

# ============================================================
# Interactive menu
# ============================================================
interactive_menu() {
    while true; do
        echo ""
        echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}║       Naxsi WAF Manager                 ║${NC}"
        echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
        echo ""

        # Quick status line
        if grep -qP '^\s*LearningMode;' "$NAXSI_RULES" 2>/dev/null; then
            echo -e "  Mode: ${YELLOW}LEARNING${NC} (not blocking)"
        else
            echo -e "  Mode: ${GREEN}BLOCKING${NC} (active protection)"
        fi

        local wl_count=0 pending_count=0 event_count=0
        [[ -f "$WHITELIST_FILE" ]] && wl_count=$(grep -cP '^\s*BasicRule' "$WHITELIST_FILE" 2>/dev/null || true)
        [[ -f "$PENDING_FILE" ]] && pending_count=$(grep -cP '^\s*BasicRule' "$PENDING_FILE" 2>/dev/null || true)
        [[ -f "$ERROR_LOG" ]] && event_count=$(grep -c 'NAXSI_FMT' "$ERROR_LOG" 2>/dev/null || true)

        echo -e "  Whitelist: ${BLUE}${wl_count}${NC} rules  |  Pending: ${YELLOW}${pending_count}${NC}  |  Log events: ${BLUE}${event_count}${NC}"
        echo ""
        echo -e "  ${GREEN}1${NC}) Enable learning mode"
        echo -e "  ${GREEN}2${NC}) Disable learning mode"
        echo -e "  ${GREEN}3${NC}) Generate whitelist from logs"
        echo -e "  ${GREEN}4${NC}) Review pending rules (interactive)"
        echo -e "  ${GREEN}5${NC}) Apply pending rules"
        echo -e "  ${GREEN}6${NC}) Show active whitelist"
        echo -e "  ${GREEN}7${NC}) Show pending rules"
        echo -e "  ${GREEN}8${NC}) Remove a whitelist rule"
        echo -e "  ${GREEN}9${NC}) Clear learning log data"
        echo -e "  ${GREEN}0${NC}) Show full status"
        echo -e "  ${DIM}q${NC}) Quit"
        echo ""
        echo -ne "  Choose [0-9/q]: "
        read -r choice

        case "$choice" in
            1) cmd_learn_on ;;
            2) cmd_learn_off ;;
            3) cmd_generate ;;
            4) cmd_review ;;
            5) cmd_apply ;;
            6) cmd_show ;;
            7) cmd_show_pending ;;
            8) cmd_remove ;;
            9) cmd_clear_logs ;;
            0) cmd_status ;;
            q|Q) echo -e "${DIM}Bye.${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid choice.${NC}" ;;
        esac
    done
}

# ============================================================
# Main
# ============================================================
main() {
    check_root
    ensure_files

    local cmd="${1:-}"

    case "$cmd" in
        status)         cmd_status ;;
        learn-on)       cmd_learn_on ;;
        learn-off)      cmd_learn_off ;;
        generate)       cmd_generate ;;
        review)         cmd_review ;;
        apply)          cmd_apply ;;
        show)           cmd_show ;;
        show-pending)   cmd_show_pending ;;
        remove)         cmd_remove ;;
        clear-logs)     cmd_clear_logs ;;
        help|--help|-h)
            echo "Usage: sudo naxsi-manager [command]"
            echo ""
            echo "Commands:"
            echo "  (none)        Interactive menu"
            echo "  status        Show current mode and statistics"
            echo "  learn-on      Enable learning mode"
            echo "  learn-off     Disable learning mode"
            echo "  generate      Parse error logs and generate whitelist rules"
            echo "  review        Interactively review pending rules"
            echo "  apply         Apply pending whitelist rules"
            echo "  show          Show active whitelist rules"
            echo "  show-pending  Show pending rules awaiting review"
            echo "  remove        Remove a whitelist rule"
            echo "  clear-logs    Clear Naxsi events from error log"
            echo "  help          Show this help"
            ;;
        "")             interactive_menu ;;
        *)
            echo "Unknown command: $cmd"
            echo "Run 'naxsi-manager help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
