ARG GO_VERSION=invalid # must be set
FROM golang:${GO_VERSION}-alpine
ARG UID=1000
ARG GID=1000
RUN addgroup -g ${GID} fuzz && adduser -D -u ${UID} -G fuzz fuzz
USER ${UID}:${GID}
WORKDIR /src
