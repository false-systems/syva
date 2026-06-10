# syntax=docker/dockerfile:1
#
# Toolchain image for building Syva: stable Rust (workspace + xtask), nightly
# with rust-src (eBPF via -Z build-std), bpf-linker, and protoc. Published as:
#
#   ghcr.io/false-systems/syva-builder:<tag>
#
# by .github/workflows/builder-image.yml. The release Dockerfile at the repo
# root builds FROM this image, so toolchain churn stays out of release builds.
# Bump the tag in both the workflow and the root Dockerfile when changing
# anything here.

FROM docker.io/library/rust:1-bookworm

ARG BPF_LINKER_VERSION=v0.10.3
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src

RUN case "${TARGETARCH}" in \
      amd64) triple=x86_64-unknown-linux-musl ;; \
      arm64) triple=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-${triple}.tar.gz" \
      | tar -xz -C /usr/local/bin \
 && bpf-linker --version

WORKDIR /src
