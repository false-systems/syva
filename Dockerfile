# syntax=docker/dockerfile:1
#
# Two-step release build. Step 1 compiles everything inside the published Syva
# toolchain image (see docker/builder.Dockerfile); step 2 copies the artifacts
# into slim runtime images:
#
#   docker build --target syva-core        -t syva-core:dev .
#   docker build --target syva-adapter-k8s -t syva-adapter-k8s:dev .
#
# The eBPF object is installed at /usr/lib/syva/syva-ebpf, the first path
# syva-core's object discovery checks. eBPF bytecode is architecture-independent
# across amd64/arm64 nodes; kernel struct offsets are resolved from BTF at
# startup, not baked in.

ARG BUILDER_IMAGE=ghcr.io/false-systems/syva-builder:v1

FROM ${BUILDER_IMAGE} AS builder
WORKDIR /src
COPY . .
RUN cargo run -p xtask -- build-ebpf
RUN cargo build --release -p syva-core -p syva-adapter-k8s -p syvactl

# syva-core: enforcement engine. Needs the syva group for socket ownership and
# a shell for the DaemonSet's stale-pin cleanup init container.
FROM docker.io/library/debian:bookworm-slim AS syva-core
RUN groupadd --system syva
COPY --from=builder /src/target/release/syva-core /usr/local/bin/syva-core
COPY --from=builder /src/target/release/syvactl /usr/local/bin/syvactl
COPY --from=builder /src/syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf /usr/lib/syva/syva-ebpf
ENTRYPOINT ["/usr/local/bin/syva-core"]

# syva-adapter-k8s: SyvaZonePolicy + pod membership reconciler.
FROM docker.io/library/debian:bookworm-slim AS syva-adapter-k8s
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/syva-k8s /usr/local/bin/syva-k8s
ENTRYPOINT ["/usr/local/bin/syva-k8s"]
