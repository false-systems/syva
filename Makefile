LIMA_NAME ?= syva-dev
LIMA_CONFIG ?= ./lima/syva.yaml
REPO_DIR := $(shell pwd)

.PHONY: fmt lint test check precommit ci linux-bpf-check proto-check check-release-docs check-ebpf-artifact-policy lima-up lima-shell lima-check lima-test lima-ebpf-build eval-build verify-runtime verify-integration verify-container-integration macos-check

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
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" cargo run -p xtask -- verify-runtime

# Privileged Linux / BPF-LSM only: deploys the local core and proves the kernel
# blocks a forbidden cross-zone file_open. Run as: sudo -E make verify-integration
verify-integration:
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" cargo run -p xtask -- verify-integration

# Privileged Linux / BPF-LSM + container runtime: proves a real container in
# zone-a is blocked from reading a zone-b file. Needs docker/nerdctl/podman.
# Run as: sudo -E make verify-container-integration
verify-container-integration:
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" cargo run -p xtask -- verify-container-integration

macos-check:
	cargo fmt --all -- --check
	cargo test -p syva-proto -p syva-ebpf-common -p syva-adapter-api
	cargo check -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syva-core-client
