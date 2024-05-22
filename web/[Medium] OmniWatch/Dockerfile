FROM debian:11.9

# Install packages
RUN apt update
RUN apt install -y wget gnupg software-properties-common apt-transport-https lsb-release ca-certificates
RUN wget -q -O - https://packagecloud.io/varnishcache/varnish60lts/gpgkey | apt-key add -
RUN echo "deb https://packagecloud.io/varnishcache/varnish60lts/debian/ buster main" >> /etc/apt/sources.list.d/varnishcache_varnish60lts.list
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys B7B3B788A8D3785C
RUN echo "deb http://repo.mysql.com/apt/debian/ buster mysql-8.0" >> /etc/apt/sources.list.d/mysql.list
RUN apt update
RUN DEBIAN_FRONTEND="noninteractive" apt install -y gcc curl git tar xz-utils supervisor varnish python3 pip mysql-server chromium
RUN rm -rf /var/lib/apt/lists/*

# Add chromium to PATH
ENV PATH="/usr/lib/chromium:${PATH}"

# Copy flag
COPY flag.txt /flag.txt

# Upgrade pip
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade setuptools

# Setup and install zig
RUN mkdir -p /zig
WORKDIR /zig
RUN wget https://ziglang.org/download/0.11.0/zig-linux-x86_64-0.11.0.tar.xz
RUN tar -xvf zig-linux-x86_64-0.11.0.tar.xz
RUN rm zig-linux-x86_64-0.11.0.tar.xz
ENV PATH="/zig/zig-linux-x86_64-0.11.0:$PATH"

# Setup readflag program
COPY config/readflag.c /
RUN gcc -o /readflag /readflag.c && chmod 4755 /readflag && rm /readflag.c

# Create challenge directory
RUN mkdir -p /app
COPY challenge /app

# Build oracle
WORKDIR /app/oracle
RUN zig build

# Install controller dependencies
WORKDIR /app/controller
RUN python3 -m pip install -r requirements.txt

# Setup supervisord
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/cache.vcl /etc/varnish/default.vcl

# Expose http port
EXPOSE 1337

# Startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]