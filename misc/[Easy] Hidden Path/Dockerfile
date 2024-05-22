FROM alpine:20240329

RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

RUN apk add --no-cache --update nodejs npm

COPY challenge/ /www/

WORKDIR /www
RUN npm install express

RUN chown -R www:www /www/

EXPOSE 1337

CMD node app.js
