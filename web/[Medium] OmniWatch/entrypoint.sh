#!/bin/bash

# Secure entrypoint
chmod 600 /entrypoint.sh

# Random password function
function genPass() {
    echo -n $RANDOM | md5sum | head -c 32
}

# Generate varnish and jwt secrets
dd if=/dev/urandom of=/etc/varnish/secret count=1
dd if=/dev/urandom bs=32 count=1 status=none | tr -dc "[:print:]" > /app/jwt_secret.txt

# Randomize flag name
mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt

# Set environment variables
export MYSQL_HOST="localhost"
export MYSQL_DATABASE="omniwatch"
export MYSQL_USER="omniwatch"
export MYSQL_PASSWORD=$(genPass)
export MODERATOR_USER=$(genPass)
export MODERATOR_PASSWORD=$(genPass)

# Initialize and start mysql
mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld
mysqld --user=mysql --console --skip-networking=0 &

# Wait for mysql to start
while ! mysqladmin ping -h"localhost" --silent; do echo "not up" && sleep .2; done

# Create mysql user
mysql -u root -h $MYSQL_HOST << EOF
CREATE USER '${MYSQL_USER}'@'${MYSQL_HOST}' IDENTIFIED BY '${MYSQL_PASSWORD}';
CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE};
GRANT ALL PRIVILEGES ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'${MYSQL_HOST}';
FLUSH PRIVILEGES;
EOF

# Migrate database
python3 seed.py

# Revoke unused permissions
mysql -u root -h $MYSQL_HOST << EOF
REVOKE ALL PRIVILEGES ON ${MYSQL_DATABASE}.* FROM '${MYSQL_USER}'@'${MYSQL_HOST}';
GRANT SELECT ON ${MYSQL_DATABASE}.users TO '${MYSQL_USER}'@'${MYSQL_HOST}';
GRANT SELECT ON ${MYSQL_DATABASE}.devices TO '${MYSQL_USER}'@'${MYSQL_HOST}';
GRANT SELECT, INSERT, UPDATE, DELETE ON ${MYSQL_DATABASE}.signatures TO '${MYSQL_USER}'@'${MYSQL_HOST}';
GRANT SELECT, UPDATE ON ${MYSQL_DATABASE}.bot_status TO '${MYSQL_USER}'@'${MYSQL_HOST}';
FLUSH PRIVILEGES;
EOF

# Start application
/usr/bin/supervisord -c /etc/supervisord.conf