# Start from the base Alpine image
FROM alpine:3.19.1

# Install Golang, Node.js, and Supervisor
RUN apk add --no-cache \
    go \
    nodejs \
    npm \
    supervisor \
    && npm install -g npm@latest

# Copy flag
COPY flag.txt /flag.txt

# Set a working directory 
WORKDIR /app/proxy

COPY challenge /app

# Compile proxy
RUN go build -o htbproxy main.go

# Set workdir
WORKDIR /app/backend

# Install npm dependencies
RUN npm install

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Create database and start supervisord
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]