#!/bin/bash

chmod 700 /entrypoint.sh

mkdir -p /run/mysqld
chown -R node:node /run/mysqld
chmod -R 755 /var/lib/mysql
chown -R node:node /var/lib/mysql
mysql_install_db --user=node --ldata=/var/lib/mysql
mysqld --user=node --console --skip-name-resolve --skip-networking=0 &

while ! mysqladmin ping -h'localhost' --silent; do echo "not up" && sleep .2; done

mysql -u root < /tmp/db.sql

/usr/bin/supervisord -c /etc/supervisord.conf