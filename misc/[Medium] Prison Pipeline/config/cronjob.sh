#!/bin/bash

# Secure entrypoint
chmod 600 /home/node/.config/cronjob.sh

# Set up variables
REGISTRY_URL="http://localhost:4873"
APP_DIR="/app"
PACKAGE_NAME="prisoner-db"

cd $APP_DIR;

while true; do
    # Check for outdated package
    OUTDATED=$(npm --registry $REGISTRY_URL outdated $PACKAGE_NAME)

    if [[ -n "$OUTDATED" ]]; then
        # Update package and restart app
        npm --registry $REGISTRY_URL update $PACKAGE_NAME
        pm2 restart prison-pipeline
    fi

    sleep 30
done