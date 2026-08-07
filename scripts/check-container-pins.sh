#!/usr/bin/env bash
set -euo pipefail

files=(
  brokers/github/deployment/docker/Dockerfile
  brokers/huggingface/deployment/docker/Dockerfile
  brokers/sudo/deployment/docker/Dockerfile
)

for file in "${files[@]}"; do
  for argument in GO_BUILDER DISTROLESS; do
    value=$(grep -E "^ARG ${argument}=" "$file" || true)
    if [[ ! "$value" =~ ^ARG\ ${argument}=[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
      echo "$file has an invalid ${argument} image pin" >&2
      exit 1
    fi
    if [[ "$value" =~ @sha256:0{64}$ ]]; then
      echo "$file has a placeholder ${argument} image digest" >&2
      exit 1
    fi
  done
done
