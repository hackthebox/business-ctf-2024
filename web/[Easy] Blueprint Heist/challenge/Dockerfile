FROM node:22

# Install system packages
RUN apt-get update && apt-get install -y \
    mariadb-client \
    mariadb-server \
    supervisor \
    xfonts-75dpi \
    xfonts-base \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb && \
    dpkg -i libssl1.1_1.1.0g-2ubuntu4_amd64.deb

RUN wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.buster_amd64.deb && \
    dpkg -i wkhtmltox_0.12.5-1.buster_amd64.deb || true  && \
    rm wkhtmltox_0.12.5-1.buster_amd64.deb

RUN mkdir /tmp/runtime && \
    chown node:node /tmp/runtime && \
    chmod 700 /tmp/runtime

RUN groupadd -r www && useradd -m -r -g www www

ENV XDG_RUNTIME_DIR=/tmp/runtime

WORKDIR /app

COPY flag.txt /root/flag.txt

COPY config/supervisord.conf /etc/supervisord.conf

COPY database/db.sql /tmp/db.sql

COPY app /app

RUN npm install

RUN chown -R node:node /app/

EXPOSE 1337

COPY --chown=root entrypoint.sh /entrypoint.sh

RUN chmod 700 /entrypoint.sh

# Setup readflag
COPY config/readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

ENTRYPOINT ["/entrypoint.sh"]