#!/bin/bash

# Set up variables
CONFIG_DIR="/home/node/.config/verdaccio"
REGISTRY_URL="http://localhost:4873"
PRISONER_DB_PKG_DIR="/home/node/prisoner-db"
CONFIG_FILE="/home/node/config.yaml"
NPM_USERNAME="registry"
NPM_EMAIL="registry@prison-pipeline.htb"
NPM_PASSWORD=$(< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

# Create necessary directories
mkdir -p $CONFIG_DIR

# Function to start verdaccio and wait for it to be ready
start_verdaccio() {
  verdaccio &
  VERDACCIO_PID=$!
  while ! curl -s $REGISTRY_URL > /dev/null; do
    sleep 1
  done
}

# Start verdaccio
start_verdaccio

# Add registry user
/usr/bin/expect <<EOD
spawn npm adduser --registry $REGISTRY_URL
expect {
  "Username:" {send "$NPM_USERNAME\r"; exp_continue}
  "Password:" {send "$NPM_PASSWORD\r"; exp_continue}
  "Email: (this IS public)" {send "$NPM_EMAIL\r"; exp_continue}
}
EOD

# Publish private package
cd $PRISONER_DB_PKG_DIR
npm publish --registry $REGISTRY_URL

# Replace config and restart verdaccio
mv $CONFIG_FILE $CONFIG_DIR/config.yaml
kill $VERDACCIO_PID
start_verdaccio

# Install dependencies
cd /app
npm --registry $REGISTRY_URL install

# Stop verdaccio
kill $VERDACCIO_PID