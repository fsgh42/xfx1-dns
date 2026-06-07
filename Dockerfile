# syntax=docker/dockerfile:1
ARG GOLANG_IMAGE=golang:1.26.1-alpine

ARG GIT_COMMIT=
ARG GIT_TAG=

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS build
WORKDIR /src
COPY . /src
ARG GIT_COMMIT
ARG GIT_TAG
RUN --mount=type=cache,target=/buildcache \
  CGO_ENABLED=0 \
  GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH} \
  GOCACHE=/buildcache \
  go build \
    -ldflags="-s -w -extldflags \"-static\" -X 'git.xfx1.de/infrastructure/xfx1-dns/internal/runtime.Commit=${GIT_COMMIT}' -X 'git.xfx1.de/infrastructure/xfx1-dns/internal/runtime.Tag=${GIT_TAG}'" \
    -o /out/ ./cmd/...

FROM scratch AS master
COPY --chmod=755 --from=build /out/master /master
CMD ["/master"]

FROM scratch AS rfc2136
COPY --chmod=755 --from=build /out/rfc2136 /rfc2136
CMD ["/rfc2136"]

FROM scratch AS slave
COPY --chmod=755 --from=build /out/slave /slave
CMD ["/slave"]

FROM scratch AS router
COPY --chmod=755 --from=build /out/router /router
CMD ["/router"]

FROM scratch AS test
COPY --chmod=755 --from=build /out/test /test
CMD ["/test"]
