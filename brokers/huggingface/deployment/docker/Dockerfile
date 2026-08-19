# syntax=docker/dockerfile:1.10
# unYOLO official hf-broker image.
#
# Build args:
#   VERSION       — release tag (e.g. hf-broker/v1.2.3)
#   SOURCE_COMMIT — the exact commit the release was cut from

ARG GO_BUILDER=golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83
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
      -o /out/hf-broker ./brokers/huggingface/cmd/hf-broker && \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.Version=${VERSION} \
        -X github.com/osolmaz/unyolo/internal/buildinfo.SourceCommit=${SOURCE_COMMIT}" \
      -o /out/git-credential-unyolo ./cmd/git-credential-unyolo

FROM ${DISTROLESS}
LABEL org.opencontainers.image.title="unyolo-hf-broker"
LABEL org.opencontainers.image.source="https://github.com/osolmaz/unyolo"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL io.unyolo.broker="hf-broker"
LABEL io.unyolo.contract="agent.v1"
USER 10001:10001
WORKDIR /
COPY --from=build --chown=root:root --chmod=0755 /out/hf-broker /usr/local/bin/hf-broker
COPY --from=build --chown=root:root --chmod=0755 /out/git-credential-unyolo /usr/local/bin/git-credential-unyolo
ENTRYPOINT ["/usr/local/bin/hf-broker"]
