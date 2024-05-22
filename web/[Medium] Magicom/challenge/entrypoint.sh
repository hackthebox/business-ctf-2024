#!/bin/ash

# Secure entrypoint
chmod 600 /entrypoint.sh

# Initialize & start MariaDB
mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld
mysql_install_db --user=mysql --ldata=/var/lib/mysql
mysqld --user=mysql --console --skip-name-resolve --skip-networking=0 &

# Wait for mysql to start
while ! mysqladmin ping -h'localhost' --silent; do echo "not up" && sleep .2; done

php /www/cli/cli.php -c /www/cli/conf.xml -m import -f /www/products.sql
rm /www/products.sql

# Start supervisord services
/usr/bin/supervisord -c /etc/supervisord.conf