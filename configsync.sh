#!/bin/bash

RSYNC=$(sudo rsync -aizhe "ssh -i /home/kien/.ssh/id_rsa" kien@192.168.18.71:/etc/nginx/ /etc/nginx/)

if [ $? -eq 0 ]; then
        if [ -n "${RSYNC}" ]; then
                /usr/sbin/nginx -s reload
                echo "reloaded."
        fi
else
        exit 1
fi
