#!/bin/bash
# Sync Nginx configuration from primary server and reload on changes.
#
# Usage: Edit the variables below, then add to crontab:
#   * * * * * /path/to/configsync.sh
#
set -euo pipefail

# --- Configuration (edit these) ---
SSH_KEY="/home/kien/.ssh/id_rsa"
REMOTE_USER="kien"
REMOTE_HOST="192.168.18.71"
# ----------------------------------

LOGFILE="/var/log/naxsi-sync.log"

CHANGES=$(rsync -aizhe "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5" \
    "${REMOTE_USER}@${REMOTE_HOST}:/etc/nginx/" /etc/nginx/ 2>&1) || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: rsync failed" >> "$LOGFILE"
    exit 1
}

if [[ -n "$CHANGES" ]]; then
    if nginx -t > /dev/null 2>&1; then
        nginx -s reload
        echo "$(date '+%Y-%m-%d %H:%M:%S') Config synced and Nginx reloaded" >> "$LOGFILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Nginx config test failed after sync" >> "$LOGFILE"
        exit 1
    fi
fi
