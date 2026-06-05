LIMA_NAME ?= syva-dev
LIMA_CONFIG ?= ./lima/syva.yaml
REPO_DIR := $(shell pwd)

.PHONY: lima-up lima-shell lima-check lima-test lima-ebpf-build eval-build verify-runtime verify-integration macos-check

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

eval-build:
	cargo run -p xtask -- eval-build

verify-runtime:
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" cargo run -p xtask -- verify-runtime

# Privileged Linux / BPF-LSM only: deploys the local core and proves the kernel
# blocks a forbidden cross-zone file_open. Run as: sudo -E make verify-integration
verify-integration:
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" cargo run -p xtask -- verify-integration

macos-check:
	cargo fmt --all -- --check
	cargo test -p syva-proto -p syva-ebpf-common -p syva-adapter-api
	cargo check -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syva-core-client
