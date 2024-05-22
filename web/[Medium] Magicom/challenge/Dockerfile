FROM alpine:3.19.1

# Setup user
RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

# Install system packages
RUN apk add --no-cache --update mariadb mariadb-client \
    supervisor nginx build-base openssl-dev

RUN apk add --no-cache --update php-fpm php-phar \
    php-mysqli php-dom php-session php-fileinfo

# Switch working environment

WORKDIR /tmp

COPY flag.txt /root/flag.txt

# Configure php-fpm and nginx
COPY config/fpm.conf /etc/php82/php-fpm.d/www.conf
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/php.ini /etc/php82/php.ini

# Copy challenge files
COPY magicom /www

# Setup permissions
RUN chown -R www:www /www/uploads /var/lib/nginx

# Expose the port nginx is listening on
EXPOSE 1337

# Populate database and start supervisord
# CMD while true; do sleep 10; done
COPY --chown=root entrypoint.sh /entrypoint.sh

# Setup readflag
COPY config/readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

ENTRYPOINT ["/entrypoint.sh"]