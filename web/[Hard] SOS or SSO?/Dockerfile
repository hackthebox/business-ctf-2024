FROM golang:1.22-alpine

COPY flag.txt /flag.txt

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"

RUN apk add --update nodejs npm gcc g++ musl-dev chromium chromium-chromedriver

# Change this after
ADD challenge/ /app

RUN cd /app/frontend/ && npm install && npm run build
RUN cd /app/backend && go env -w CGO_ENABLED=1 && go build -ldflags='-s -w -extldflags "-static"' .

EXPOSE 8080

COPY --chown=root ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh