FROM python:3.11-alpine

RUN apk add --no-cache socat
RUN addgroup -g 1000 ctf && adduser -u 1000 -G ctf -h /home/ctf -D ctf

ADD --chown=ctf challenge/* /home/ctf/
RUN chown -R root:ctf /home/ctf
WORKDIR /home/ctf

EXPOSE 1337/tcp

ENTRYPOINT ["socat", "TCP-LISTEN:1337,fork,reuseaddr", "EXEC:'python3 main.py'"]
