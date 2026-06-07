ARG GO_VERSION=invalid # must be set
FROM golang:${GO_VERSION}-alpine
RUN \
  CGO_ENABLED=0 go install github.com/segmentio/golines@latest && \
  CGO_ENABLED=0 go install mvdan.cc/gofumpt@latest && \
  CGO_ENABLED=0 go install github.com/bombsimon/wsl/v4/cmd/wsl@latest
RUN adduser -D -u 1000 formatter
USER 1000
WORKDIR /src
