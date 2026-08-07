# syntax=docker/dockerfile:1.10
# unYOLO official gh-broker image.
#
# Build args:
#   VERSION       — release tag (e.g. gh-broker/v1.2.3)
#   SOURCE_COMMIT — the exact commit the release was cut from
#
# The build is reproducible from a checkout at SOURCE_COMMIT. Both the broker
# and its git-credential-unyolo companion are compiled with -trimpath and no
# CGO. The resulting image runs as an unprivileged fixed identity and holds
# only the two binaries plus the certificate roots.

# Pinned Go builder for reproducible cross-compilation.
ARG GO_BUILDER=golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
ARG DISTROLESS=gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

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
      -o /out/gh-broker ./brokers/github/cmd/gh-broker && \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.Version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.SourceCommit=${SOURCE_COMMIT}" \
      -o /out/git-credential-unyolo ./cmd/git-credential-unyolo

FROM ${DISTROLESS}
LABEL org.opencontainers.image.title="unyolo-gh-broker"
LABEL org.opencontainers.image.source="https://github.com/osolmaz/unyolo"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.unyolo.broker="gh-broker"
LABEL io.unyolo.contract="agent.v1"
USER 10001:10001
WORKDIR /
COPY --from=build --chown=root:root --chmod=0755 /out/gh-broker /usr/local/bin/gh-broker
COPY --from=build --chown=root:root --chmod=0755 /out/git-credential-unyolo /usr/local/bin/git-credential-unyolo
ENTRYPOINT ["/usr/local/bin/gh-broker"]
