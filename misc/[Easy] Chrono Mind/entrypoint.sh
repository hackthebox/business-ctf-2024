#!/bin/bash

# Remove self
rm -f /entrypoint.sh

SECRET=$(python -c "import secrets; print(secrets.randbelow(10**16))" | tr -d '\n')

sed -i "s/REDACTED_SECRET/$SECRET/g" /home/chrono/chrono-mind/config.py

# Start supervisord and services
/usr/bin/supervisord -c /etc/supervisord.conf