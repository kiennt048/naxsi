#!/bin/bash
#
# Naxsi WAF + Nginx + Keepalived — Automated Installer
# Supports: Ubuntu 22.04 (Jammy) and Ubuntu 24.04 (Noble)
#
# Usage:
#   sudo bash install.sh [OPTIONS]
#
# Options:
#   --role primary|backup     Server role (default: primary)
#   --vip ADDRESS             Virtual IP for Keepalived (default: 192.168.18.70)
#   --priority NUMBER         VRRP priority, higher = preferred master (default: 100 for primary, 50 for backup)
#   --interface IFACE         Network interface for VRRP (default: auto-detected)
#   --server-ip ADDRESS       This server's real IP (default: auto-detected)
#   --backend ADDR:PORT       Backend server (repeatable, e.g. --backend 10.0.0.2:80 --backend 10.0.0.3:80)
#   --peer-ip ADDRESS         Peer server IP for config sync (required for backup role)
#   --peer-user USER          SSH user on peer server (default: current user)
#   --vrrp-password PASS      VRRP auth password (default: randomly generated)
#   --naxsi-version VER       Naxsi version to install (default: 1.7)
#   --skip-keepalived         Skip Keepalived installation
#   --skip-sync               Skip config sync setup
#   --uninstall               Remove Naxsi module and config (keeps Nginx)
#   --help                    Show this help message
#
set -euo pipefail

# ============================================================
# Constants
# ============================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/naxsi-install.log"
readonly REQUIRED_UBUNTU_VERSIONS=("22.04" "24.04")
readonly DEFAULT_NAXSI_VERSION="1.7"

# ============================================================
# Color output
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2; }
log_step()    { echo -e "${BLUE}[STEP]${NC}  $*" | tee -a "$LOG_FILE"; }

# ============================================================
# Defaults
# ============================================================
ROLE="primary"
VIP="192.168.18.70"
PRIORITY=""
INTERFACE=""
SERVER_IP=""
BACKENDS=()
PEER_IP=""
PEER_USER="${SUDO_USER:-$USER}"
VRRP_PASSWORD=""
NAXSI_VERSION="$DEFAULT_NAXSI_VERSION"
SKIP_KEEPALIVED=false
SKIP_SYNC=false
UNINSTALL=false

# ============================================================
# Parse arguments
# ============================================================
usage() {
    sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \?//'
    sed -n '/^# Options:/,/^#$/p' "$0" | sed 's/^# \?//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role)           ROLE="$2"; shift 2 ;;
            --vip)            VIP="$2"; shift 2 ;;
            --priority)       PRIORITY="$2"; shift 2 ;;
            --interface)      INTERFACE="$2"; shift 2 ;;
            --server-ip)      SERVER_IP="$2"; shift 2 ;;
            --backend)        BACKENDS+=("$2"); shift 2 ;;
            --peer-ip)        PEER_IP="$2"; shift 2 ;;
            --peer-user)      PEER_USER="$2"; shift 2 ;;
            --vrrp-password)  VRRP_PASSWORD="$2"; shift 2 ;;
            --naxsi-version)  NAXSI_VERSION="$2"; shift 2 ;;
            --skip-keepalived) SKIP_KEEPALIVED=true; shift ;;
            --skip-sync)      SKIP_SYNC=true; shift ;;
            --uninstall)      UNINSTALL=true; shift ;;
            --help|-h)        usage ;;
            *)                log_error "Unknown option: $1"; usage ;;
        esac
    done
}

# ============================================================
# Validation helpers
# ============================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)."
        exit 1
    fi
}

check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "ubuntu" ]]; then
        log_error "This script only supports Ubuntu. Detected: $ID"
        exit 1
    fi

    local version_supported=false
    for ver in "${REQUIRED_UBUNTU_VERSIONS[@]}"; do
        if [[ "$VERSION_ID" == "$ver" ]]; then
            version_supported=true
            break
        fi
    done

    if ! $version_supported; then
        log_error "Ubuntu $VERSION_ID is not supported. Supported versions: ${REQUIRED_UBUNTU_VERSIONS[*]}"
        exit 1
    fi

    log_info "Detected Ubuntu $VERSION_ID ($VERSION_CODENAME)"
}

detect_interface() {
    if [[ -z "$INTERFACE" ]]; then
        INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
        if [[ -z "$INTERFACE" ]]; then
            log_error "Could not auto-detect network interface. Use --interface."
            exit 1
        fi
        log_info "Auto-detected network interface: $INTERFACE"
    fi
}

detect_server_ip() {
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [[ -z "$SERVER_IP" ]]; then
            log_error "Could not auto-detect server IP. Use --server-ip."
            exit 1
        fi
        log_info "Auto-detected server IP: $SERVER_IP"
    fi
}

validate_args() {
    if [[ "$ROLE" != "primary" && "$ROLE" != "backup" ]]; then
        log_error "--role must be 'primary' or 'backup'."
        exit 1
    fi

    if [[ -z "$PRIORITY" ]]; then
        if [[ "$ROLE" == "primary" ]]; then
            PRIORITY=100
        else
            PRIORITY=50
        fi
    fi

    if [[ "$ROLE" == "backup" && -z "$PEER_IP" && "$SKIP_SYNC" == false ]]; then
        log_warn "No --peer-ip set for backup role. Config sync will be skipped."
        SKIP_SYNC=true
    fi

    if [[ -z "$VRRP_PASSWORD" ]]; then
        VRRP_PASSWORD=$(openssl rand -hex 4)
        log_warn "Generated VRRP password: $VRRP_PASSWORD (save this — both nodes must use the same password)"
    fi

    if [[ ${#BACKENDS[@]} -eq 0 ]]; then
        log_warn "No --backend specified. Using placeholder 127.0.0.1:8080. Edit /etc/nginx/nginx.conf after install."
        BACKENDS=("127.0.0.1:8080")
    fi
}

# ============================================================
# Install functions
# ============================================================
install_dependencies() {
    log_step "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq \
        build-essential \
        libmaxminddb-dev \
        libpcre3-dev \
        libpcre3 \
        libssl-dev \
        zlib1g \
        zlib1g-dev \
        wget \
        curl \
        gnupg \
        rsync \
        cron \
        git \
        2>&1 | tee -a "$LOG_FILE"
    log_info "Dependencies installed."
}

install_nginx() {
    log_step "Installing Nginx..."
    apt-get install -y -qq nginx 2>&1 | tee -a "$LOG_FILE"
    systemctl enable nginx
    log_info "Nginx installed: $(nginx -v 2>&1)"
}

get_nginx_version() {
    nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+'
}

build_naxsi_module() {
    log_step "Building Naxsi module v${NAXSI_VERSION}..."
    local build_dir
    build_dir=$(mktemp -d /tmp/naxsi-build.XXXXXX)
    local nginx_ver
    nginx_ver=$(get_nginx_version)

    cd "$build_dir"

    # Download Naxsi source
    log_info "Downloading Naxsi v${NAXSI_VERSION}..."
    wget -q "https://github.com/wargio/naxsi/releases/download/${NAXSI_VERSION}/naxsi-${NAXSI_VERSION}-src-with-deps.tar.gz" \
        -O "naxsi-${NAXSI_VERSION}-src-with-deps.tar.gz"

    # Download Nginx source (must match installed version)
    log_info "Downloading Nginx ${nginx_ver} source..."
    wget -q "https://nginx.org/download/nginx-${nginx_ver}.tar.gz" \
        -O "nginx-${nginx_ver}.tar.gz"

    # Extract
    mkdir -p "naxsi-${NAXSI_VERSION}"
    tar -C "naxsi-${NAXSI_VERSION}" -xzf "naxsi-${NAXSI_VERSION}-src-with-deps.tar.gz"
    tar -xzf "nginx-${nginx_ver}.tar.gz"

    # Build
    cd "nginx-${nginx_ver}"

    ./configure \
        --with-compat \
        --add-dynamic-module="../naxsi-${NAXSI_VERSION}/naxsi_src/" \
        2>&1 | tee -a "$LOG_FILE"

    make modules 2>&1 | tee -a "$LOG_FILE"

    # Install module
    mkdir -p /etc/nginx/modules
    cp objs/ngx_http_naxsi_module.so /etc/nginx/modules/ngx_http_naxsi_module.so
    chmod 644 /etc/nginx/modules/ngx_http_naxsi_module.so

    # Cleanup
    cd /
    rm -rf "$build_dir"

    log_info "Naxsi module built and installed to /etc/nginx/modules/"
}

install_naxsi_config() {
    log_step "Installing Naxsi configuration..."

    # Core rules
    cp "${SCRIPT_DIR}/naxsi_core.rules" /etc/nginx/naxsi_core.rules
    chmod 644 /etc/nginx/naxsi_core.rules

    # Blocking rules (from upstream 1.7)
    for rulefile in naxsi_blocking_scanner.rules naxsi_blocking_web.rules \
                    naxsi_blocking_wordpress.rules naxsi_blocking_php.rules \
                    naxsi_blocking_sql.rules; do
        if [[ -f "${SCRIPT_DIR}/${rulefile}" ]]; then
            cp "${SCRIPT_DIR}/${rulefile}" "/etc/nginx/${rulefile}"
            chmod 644 "/etc/nginx/${rulefile}"
        fi
    done

    # Runtime rules
    cp "${SCRIPT_DIR}/naxsi.rules" /etc/nginx/naxsi.rules
    chmod 644 /etc/nginx/naxsi.rules

    # Empty whitelist file (managed by naxsi-manager)
    touch /etc/nginx/naxsi_whitelist.rules
    chmod 644 /etc/nginx/naxsi_whitelist.rules

    # Block page
    cp "${SCRIPT_DIR}/block.html" /var/www/html/block.html
    chmod 644 /var/www/html/block.html

    # Install naxsi-manager tool
    cp "${SCRIPT_DIR}/naxsi-manager.sh" /usr/local/bin/naxsi-manager
    chmod 755 /usr/local/bin/naxsi-manager

    # Install AI security agent
    cp "${SCRIPT_DIR}/naxsi-ai-agent.sh" /usr/local/bin/naxsi-ai-agent
    chmod 755 /usr/local/bin/naxsi-ai-agent
    mkdir -p /var/lib/naxsi-ai-agent/reports

    # Install CI/CD rule generation tool
    cp "${SCRIPT_DIR}/naxsi-ci.sh" /usr/local/bin/naxsi-ci
    chmod 755 /usr/local/bin/naxsi-ci

    # Generate nginx.conf
    generate_nginx_conf

    log_info "Naxsi configuration installed."
    log_info "Use 'sudo naxsi-manager' to manage learning mode and whitelists."
}

generate_nginx_conf() {
    log_info "Generating nginx.conf..."

    local backend_block=""
    for backend in "${BACKENDS[@]}"; do
        backend_block+="        server ${backend};\n"
    done

    cat > /etc/nginx/nginx.conf <<NGINX_EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

# Load Naxsi WAF module
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    # --- Basic Settings ---
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 10m;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # --- SSL Settings ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # --- Logging ---
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    # --- Timeouts ---
    keepalive_timeout 65;
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;

    # --- Gzip ---
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 4;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # --- Security Headers (applied globally) ---
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # --- Naxsi Core Rules ---
    include /etc/nginx/naxsi_core.rules;

    # --- Naxsi Blocking Rules (from upstream 1.7) ---
    include /etc/nginx/naxsi_blocking_scanner.rules;
    include /etc/nginx/naxsi_blocking_web.rules;
    # include /etc/nginx/naxsi_blocking_wordpress.rules;  # Uncomment if running WordPress
    include /etc/nginx/naxsi_blocking_php.rules;
    include /etc/nginx/naxsi_blocking_sql.rules;

    # --- Additional configs ---
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;

    # --- Upstream backends ---
    upstream backend {
$(echo -e "$backend_block")    }

    server {
        listen ${VIP}:80;

        location / {
            include /etc/nginx/naxsi.rules;
            include /etc/nginx/naxsi_whitelist.rules;
            proxy_pass http://backend;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        location /block.html {
            root /var/www/html;
            internal;
        }
    }
}
NGINX_EOF

    chmod 644 /etc/nginx/nginx.conf
}

install_keepalived() {
    if $SKIP_KEEPALIVED; then
        log_info "Skipping Keepalived installation (--skip-keepalived)."
        return
    fi

    log_step "Installing and configuring Keepalived..."
    apt-get install -y -qq keepalived 2>&1 | tee -a "$LOG_FILE"
    systemctl enable keepalived

    # Install health check script
    install_check_script

    # Generate keepalived.conf
    local state="BACKUP"
    if [[ "$ROLE" == "primary" ]]; then
        state="MASTER"
    fi

    cat > /etc/keepalived/keepalived.conf <<KEEPALIVED_EOF
global_defs {
    router_id naxsi_${ROLE}
    script_user root
    enable_script_security
}

vrrp_script check_nginx {
    script "/etc/keepalived/check_nginx.sh"
    interval 2
    weight 50
    fall 3
    rise 2
}

vrrp_instance naxsi_ha {
    state ${state}
    interface ${INTERFACE}
    unicast_src_ip ${SERVER_IP}
    virtual_router_id 101
    priority ${PRIORITY}
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass ${VRRP_PASSWORD}
    }
    virtual_ipaddress {
        ${VIP}
    }
    track_script {
        check_nginx
    }
}
KEEPALIVED_EOF

    chmod 640 /etc/keepalived/keepalived.conf
    log_info "Keepalived configured (role=${ROLE}, priority=${PRIORITY}, vip=${VIP})."
}

install_check_script() {
    cat > /etc/keepalived/check_nginx.sh <<'CHECK_EOF'
#!/bin/bash
# Health check for Keepalived — exits 1 if Nginx is not running
if ! pidof nginx > /dev/null 2>&1; then
    exit 1
fi
exit 0
CHECK_EOF

    chmod 755 /etc/keepalived/check_nginx.sh
}

setup_config_sync() {
    if $SKIP_SYNC; then
        log_info "Skipping config sync setup (--skip-sync)."
        return
    fi

    if [[ "$ROLE" != "backup" ]]; then
        log_info "Config sync is only set up on backup nodes. Skipping."
        return
    fi

    log_step "Setting up config synchronization..."

    local home_dir
    home_dir=$(eval echo "~${PEER_USER}")
    local ssh_key="${home_dir}/.ssh/id_rsa"

    # Generate SSH key if not present
    if [[ ! -f "$ssh_key" ]]; then
        log_info "Generating SSH key for ${PEER_USER}..."
        sudo -u "$PEER_USER" ssh-keygen -t rsa -b 4096 -f "$ssh_key" -N "" -q
        log_warn "Copy the public key to the primary server:"
        log_warn "  ssh-copy-id ${PEER_USER}@${PEER_IP}"
    fi

    # Install sync script
    cat > /usr/local/bin/naxsi-config-sync.sh <<SYNC_EOF
#!/bin/bash
# Naxsi config sync — pulls Nginx config from primary server
set -euo pipefail

LOGFILE="/var/log/naxsi-sync.log"
SSH_KEY="${ssh_key}"
REMOTE_USER="${PEER_USER}"
REMOTE_HOST="${PEER_IP}"

exec >> "\$LOGFILE" 2>&1

CHANGES=\$(rsync -aizhe "ssh -i \$SSH_KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5" \\
    "\${REMOTE_USER}@\${REMOTE_HOST}:/etc/nginx/" /etc/nginx/ 2>&1) || {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') ERROR: rsync failed"
    exit 1
}

if [[ -n "\$CHANGES" ]]; then
    if nginx -t > /dev/null 2>&1; then
        nginx -s reload
        echo "\$(date '+%Y-%m-%d %H:%M:%S') Config synced and Nginx reloaded"
    else
        echo "\$(date '+%Y-%m-%d %H:%M:%S') ERROR: Nginx config test failed after sync"
        exit 1
    fi
fi
SYNC_EOF

    chmod 750 /usr/local/bin/naxsi-config-sync.sh

    # Add cron job (every minute)
    local cron_entry="* * * * * /usr/local/bin/naxsi-config-sync.sh"
    if ! crontab -l 2>/dev/null | grep -qF "naxsi-config-sync"; then
        (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
        log_info "Cron job added for config sync (every minute)."
    else
        log_info "Cron job for config sync already exists."
    fi

    log_info "Config sync installed at /usr/local/bin/naxsi-config-sync.sh"
}

# ============================================================
# Uninstall
# ============================================================
do_uninstall() {
    log_step "Uninstalling Naxsi components..."

    rm -f /etc/nginx/modules/ngx_http_naxsi_module.so
    rm -f /etc/nginx/naxsi_core.rules
    rm -f /etc/nginx/naxsi.rules
    rm -f /etc/nginx/naxsi_whitelist.rules
    rm -f /etc/nginx/naxsi_whitelist_pending.rules
    rm -f /etc/nginx/naxsi_blocking_*.rules
    rm -f /var/www/html/block.html
    rm -f /usr/local/bin/naxsi-config-sync.sh
    rm -f /usr/local/bin/naxsi-manager
    rm -f /usr/local/bin/naxsi-ai-agent
    rm -f /usr/local/bin/naxsi-ci
    rm -rf /etc/nginx/naxsi_backups
    rm -rf /var/lib/naxsi-ai-agent

    # Remove cron entry
    if crontab -l 2>/dev/null | grep -qF "naxsi-config-sync"; then
        crontab -l | grep -vF "naxsi-config-sync" | crontab -
        log_info "Removed config sync cron job."
    fi

    log_warn "Naxsi removed. Nginx is still installed — update nginx.conf to remove Naxsi references."
    log_warn "Keepalived is still installed — remove manually if needed: apt remove keepalived"
}

# ============================================================
# Service management
# ============================================================
start_services() {
    log_step "Testing and starting services..."

    # Test Nginx config
    if nginx -t 2>&1 | tee -a "$LOG_FILE"; then
        systemctl restart nginx
        log_info "Nginx started successfully."
    else
        log_error "Nginx configuration test failed. Check /etc/nginx/nginx.conf."
        exit 1
    fi

    # Start Keepalived
    if ! $SKIP_KEEPALIVED; then
        systemctl restart keepalived
        log_info "Keepalived started."
    fi

    # Start cron
    systemctl restart cron
}

print_summary() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN} Naxsi WAF Installation Complete${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo -e "  Role:            ${BLUE}${ROLE}${NC}"
    echo -e "  Virtual IP:      ${BLUE}${VIP}${NC}"
    echo -e "  Server IP:       ${BLUE}${SERVER_IP}${NC}"
    echo -e "  Interface:       ${BLUE}${INTERFACE}${NC}"
    echo -e "  VRRP Priority:   ${BLUE}${PRIORITY}${NC}"
    echo -e "  VRRP Password:   ${BLUE}${VRRP_PASSWORD}${NC}"
    echo -e "  Naxsi Version:   ${BLUE}${NAXSI_VERSION}${NC}"
    echo -e "  Nginx Version:   ${BLUE}$(get_nginx_version)${NC}"
    echo ""
    echo -e "  Backends:"
    for b in "${BACKENDS[@]}"; do
        echo -e "    - ${BLUE}${b}${NC}"
    done
    echo ""
    echo -e "  Config files:"
    echo "    /etc/nginx/nginx.conf"
    echo "    /etc/nginx/naxsi.rules"
    echo "    /etc/nginx/naxsi_core.rules"
    if ! $SKIP_KEEPALIVED; then
        echo "    /etc/keepalived/keepalived.conf"
    fi
    echo ""
    echo -e "  Logs:"
    echo "    /var/log/nginx/access.log"
    echo "    /var/log/nginx/error.log"
    echo "    /var/log/naxsi-install.log"
    if ! $SKIP_SYNC && [[ "$ROLE" == "backup" ]]; then
        echo "    /var/log/naxsi-sync.log"
    fi
    echo ""

    if ! $SKIP_KEEPALIVED; then
        echo -e "${YELLOW}  IMPORTANT: Use the same --vrrp-password on both nodes!${NC}"
        echo ""
    fi

    if ! $SKIP_SYNC && [[ "$ROLE" == "backup" ]]; then
        echo -e "${YELLOW}  IMPORTANT: Copy SSH key to primary server:${NC}"
        echo -e "${YELLOW}    ssh-copy-id ${PEER_USER}@${PEER_IP}${NC}"
        echo ""
    fi

    echo -e "  Test WAF is working:"
    echo "    curl 'http://${VIP}/?q=<script>alert(1)</script>'"
    echo "    (should be blocked)"
    echo ""
    echo -e "  ${BLUE}Manage learning mode & whitelists:${NC}"
    echo "    sudo naxsi-manager"
    echo ""
    echo -e "  ${BLUE}AI Security Agent (on-demand analysis):${NC}"
    echo "    sudo naxsi-ai-agent analyze          # One-shot log analysis"
    echo "    sudo naxsi-ai-agent auto-whitelist   # Auto-apply safe rules"
    echo "    sudo naxsi-ai-agent investigate <ip> # Investigate a blocked IP"
    echo "    sudo naxsi-ai-agent request <ip>     # User access request"
    echo ""
    echo -e "  ${BLUE}CI/CD auto rule generation:${NC}"
    echo "    sudo naxsi-ci auto --test-cmd 'npm test' --output rules.txt"
    echo "    sudo naxsi-ci validate --rules rules.txt"
    echo "    sudo naxsi-ci merge --rules rules.txt"
    echo ""
}

# ============================================================
# Main
# ============================================================
main() {
    echo "" > "$LOG_FILE"

    parse_args "$@"
    check_root

    if $UNINSTALL; then
        do_uninstall
        exit 0
    fi

    check_ubuntu_version
    detect_interface
    detect_server_ip
    validate_args

    echo ""
    log_step "Starting Naxsi WAF installation..."
    echo ""

    install_dependencies
    install_nginx
    build_naxsi_module
    install_naxsi_config
    install_keepalived
    setup_config_sync
    start_services
    print_summary
}

main "$@"
