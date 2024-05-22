FROM node@sha256:4b232062fa976e3a966c49e9b6279efa56c8d207a67270868f51b3d155c4e33d

# Install packages
RUN apt-get update \
    && apt-get install -y wget curl supervisor gnupg gcc expect nginx \
    && rm -rf /var/lib/apt/lists/*

# Install global packages
RUN npm install -g verdaccio pm2

# Setup Nginx
COPY config/nginx.conf /etc/nginx/nginx.conf
RUN mkdir /var/run/nginx && chown www-data:www-data /var/run/nginx

# Setup app
USER root
RUN mkdir -p /app

# Add application
WORKDIR /app
COPY challenge/application .
RUN chown -R node:node /app

# Copy private package
COPY challenge/prisoner-db /home/node/prisoner-db

# Setup registry and install dependencies
USER node
COPY config/setup-registry.sh /home/node/setup-registry.sh
COPY config/verdaccio.yaml /home/node/config.yaml
RUN /bin/bash /home/node/setup-registry.sh

# Copy flag
USER root
COPY flag.txt /root/flag

# Add readflag binary
COPY config/readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

# Copy cronjob script
COPY config/cronjob.sh /home/node/cronjob.sh
RUN chmod +x /home/node/cronjob.sh

# Setup superivsord
COPY config/supervisord.conf /etc/supervisord.conf

# Expose the port node-js is reachable on
EXPOSE 1337

# Start the node-js application
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
