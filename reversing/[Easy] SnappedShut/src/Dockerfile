FROM node:21-alpine as build
COPY snapshot.js /
RUN node --snapshot-blob snapshot.blob --build-snapshot snapshot.js

FROM scratch
COPY --from=build /snapshot.blob /
