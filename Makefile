LIMA_NAME ?= syva-dev
LIMA_CONFIG ?= ./lima/syva.yaml
REPO_DIR := $(shell pwd)

LIMA_SH = limactl shell $(LIMA_NAME) bash -lc
LIMA_SUDO = export PATH="$$HOME/.cargo/bin:$$PATH"; cd "$(REPO_DIR)"; sudo -E env PATH="$$PATH"

# Privileged verify targets run under `sudo`, which resets HOME to /root
# (always_set_home) and strips PATH (secure_path). Use the invoking user's
# rustup toolchains — theirs is the one this checkout builds with, and a
# leftover /root/.rustup with no default toolchain must not shadow it.
VERIFY_ENV = export PATH="$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin:$$PATH"; \
	if [ -n "$$SUDO_USER" ] && [ -d "/home/$$SUDO_USER/.rustup" ]; then \
		export RUSTUP_HOME="/home/$$SUDO_USER/.rustup" CARGO_HOME="/home/$$SUDO_USER/.cargo"; \
	fi

.PHONY: fmt lint test check precommit ci linux-bpf-check proto-check check-api-docs check-syvactl-contract check-openapi check-release-docs check-ebpf-artifact-policy lima-up lima-shell lima-check lima-test lima-ebpf-build lima-bootstrap lima-deploy lima-verify-deployment lima-undeploy lima-reset lima-smoke eval-build verify-runtime verify-integration verify-container-integration verify-k8s-membership verify-audit-mode verify-network-lock verify-egress-cidr verify-cross-zone-tcp verify-cgroup-escape verify-inode-identity verify-deployment macos-check

fmt:
	cargo run -p xtask -- fmt

lint:
	cargo run -p xtask -- lint

test:
	cargo run -p xtask -- test

check:
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) test

precommit:
	cargo run -p xtask -- precommit

ci:
	cargo run -p xtask -- ci

linux-bpf-check:
	cargo run -p xtask -- linux-bpf-check

eval-build:
	cargo run -p xtask -- eval-build

proto-check:
	cargo run -p xtask -- check-proto

check-api-docs:
	cargo run -p xtask -- check-api-docs

check-syvactl-contract:
	cargo run -p xtask -- check-syvactl-contract

check-openapi:
	cargo run -p xtask -- check-openapi

check-release-docs:
	cargo run -p xtask -- check-release-docs

check-ebpf-artifact-policy:
	cargo run -p xtask -- check-ebpf-artifact-policy

lima-up:
	limactl start --name=$(LIMA_NAME) $(LIMA_CONFIG)

lima-shell:
	limactl shell $(LIMA_NAME)

lima-check:
	limactl shell $(LIMA_NAME) bash -lc 'set -euxo pipefail; cd "$(REPO_DIR)"; export PATH="$$HOME/.cargo/bin:$$PATH"; cargo run -p xtask -- ci'

lima-test:
	limactl shell $(LIMA_NAME) bash -lc 'set -euxo pipefail; cd "$(REPO_DIR)"; export PATH="$$HOME/.cargo/bin:$$PATH"; cargo run -p xtask -- test'

lima-ebpf-build:
	limactl shell $(LIMA_NAME) bash -lc 'set -euxo pipefail; cd "$(REPO_DIR)"; export PATH="$$HOME/.cargo/bin:$$PATH"; cargo run -p xtask -- build-ebpf'

verify-runtime:
	$(VERIFY_ENV); cargo run -p xtask -- verify-runtime

# Privileged Linux / BPF-LSM only: deploys the local core and proves the kernel
# blocks a forbidden cross-zone file_open. Run as: sudo -E make verify-integration
verify-integration:
	$(VERIFY_ENV); cargo run -p xtask -- verify-integration

# Privileged Linux / BPF-LSM + container runtime: proves a real container in
# zone-a is blocked from reading a zone-b file. Needs docker/nerdctl/podman.
# Run as: sudo -E make verify-container-integration
verify-container-integration:
	$(VERIFY_ENV); cargo run -p xtask -- verify-container-integration

# Privileged Linux / BPF-LSM only: proves a network-locked zone reaches only
# the destinations its egress CIDR allowlist permits.
# Run as: sudo -E make verify-egress-cidr
verify-egress-cidr:
	$(VERIFY_ENV); cargo run -p xtask -- verify-egress-cidr

# Privileged Linux / BPF-LSM only: proves exact IPv4 destination IPs resolve to
# zones and socket_connect applies the existing zone-pair rule.
# Run as: sudo -E make verify-cross-zone-tcp
verify-cross-zone-tcp:
	$(VERIFY_ENV); cargo run -p xtask -- verify-cross-zone-tcp

# Privileged Linux / BPF-LSM only: proves a zoned task migrating out of its
# cgroup is DETECTED (counter + degraded health). Detection only, not blocked.
# Run as: sudo -E make verify-cgroup-escape
verify-cgroup-escape:
	$(VERIFY_ENV); cargo run -p xtask -- verify-cgroup-escape

# Privileged Linux / BPF-LSM only: proves an Isolated zone is network-locked
# (connect/sendmsg/bind to non-loopback denied) while a Bridged zone is open.
# Run as: sudo -E make verify-network-lock
verify-network-lock:
	$(VERIFY_ENV); cargo run -p xtask -- verify-network-lock

# Privileged Linux / BPF-LSM only: proves composite (dev, ino) file identity —
# a cross-filesystem inode-number collision is not zone-confused.
# Run as: sudo -E make verify-inode-identity
verify-inode-identity:
	$(VERIFY_ENV); cargo run -p xtask -- verify-inode-identity

# Privileged Linux / BPF-LSM only: proves audit mode records a cross-zone
# would-deny decision WITHOUT blocking the operation.
# Run as: sudo -E make verify-audit-mode
verify-audit-mode:
	$(VERIFY_ENV); cargo run -p xtask -- verify-audit-mode

# Privileged Linux / BPF-LSM + single-node Kubernetes: proves syva-k8s attaches
# an annotated pod and the kernel blocks its forbidden cross-zone file_open.
# Needs kubectl against a cluster running on this node. Run as:
# sudo -E make verify-k8s-membership
verify-k8s-membership:
	$(VERIFY_ENV); cargo run -p xtask -- verify-k8s-membership

# Verify an ALREADY-DEPLOYED syva-core (does not start its own core).
# Needs SYVA_SOCKET (default /run/syva/syva-core.sock) + a container runtime.
# Run as: sudo -E make verify-deployment   (after `make lima-deploy`)
verify-deployment:
	$(VERIFY_ENV); \
	  SYVA_SOCKET="$${SYVA_SOCKET:-/run/syva/syva-core.sock}" cargo run -p xtask -- verify-deployment

# ---- Lima development deployment lifecycle (single-node, dev only) ----

lima-bootstrap:
	$(LIMA_SH) 'set -euo pipefail; export PATH="$$HOME/.cargo/bin:$$PATH"; cd "$(REPO_DIR)"; bash deploy/lima/bootstrap.sh'

lima-deploy:
	$(LIMA_SH) 'set -euo pipefail; export PATH="$$HOME/.cargo/bin:$$PATH"; cd "$(REPO_DIR)"; bash deploy/lima/deploy.sh'

lima-verify-deployment:
	$(LIMA_SH) '$(LIMA_SUDO) SYVA_SOCKET=/run/syva/syva-core.sock cargo run -p xtask -- verify-deployment'

lima-undeploy:
	$(LIMA_SH) 'set -uo pipefail; cd "$(REPO_DIR)"; bash deploy/lima/undeploy.sh'

lima-reset:
	-$(LIMA_SH) 'set -uo pipefail; cd "$(REPO_DIR)"; bash deploy/lima/undeploy.sh'
	@echo "lima-reset: undeployed. To recreate the VM: limactl stop $(LIMA_NAME) && limactl start $(LIMA_CONFIG)"

# One-command deployment proof: bootstrap -> deploy -> verify -> undeploy.
lima-smoke:
	$(MAKE) lima-bootstrap
	$(MAKE) lima-deploy
	$(MAKE) lima-verify-deployment
	$(MAKE) lima-undeploy

macos-check:
	cargo fmt --all -- --check
	cargo test -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syvactl
	cargo check -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syva-core-client -p syvactl
