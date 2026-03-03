#!/bin/bash
# Health check for Keepalived — exits 1 if Nginx is not running.
if ! pidof nginx > /dev/null 2>&1; then
    exit 1
fi
exit 0
