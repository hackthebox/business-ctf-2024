FROM rust:1.78.0-slim-bullseye as builder
ADD src.rs /
RUN rustc src.rs -Copt-level=2 -Cdebug-assertions=n -Coverflow-checks=y -Cpanic=unwind -o dontpanic

FROM scratch
COPY --from=builder /dontpanic /
