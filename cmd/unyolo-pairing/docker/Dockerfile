# syntax=docker/dockerfile:1.10
# unYOLO official pairing service image.

ARG GO_BUILDER=golang:1.26.5-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000
ARG DISTROLESS=gcr.io/distroless/static-debian12:nonroot@sha256:0000000000000000000000000000000000000000000000000000000000000000

FROM ${GO_BUILDER} AS build
ARG VERSION=dev
ARG SOURCE_COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.Version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.SourceCommit=${SOURCE_COMMIT}" \
      -o /out/unyolo-pairing ./cmd/unyolo-pairing

FROM ${DISTROLESS}
LABEL org.opencontainers.image.title="unyolo-pairing"
LABEL org.opencontainers.image.source="https://github.com/osolmaz/unyolo"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.unyolo.broker="pairing"
USER 10001:10001
WORKDIR /
COPY --from=build --chown=root:root --chmod=0755 /out/unyolo-pairing /usr/local/bin/unyolo-pairing
ENTRYPOINT ["/usr/local/bin/unyolo-pairing"]
