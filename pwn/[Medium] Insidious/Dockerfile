# NOTE: This should NOT be hosted on regular infra without testing
# It relies on specific CPU implementation details, and is more likely
# to work on Intel than AMD systems

FROM ubuntu:22.04

RUN useradd -m ctf -u 1000
WORKDIR /home/ctf

COPY challenge .
RUN chmod u+s ./insidious && chmod 0400 ./flag.txt
USER ctf
ENTRYPOINT ["./insidious"]
