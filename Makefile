LIMA_NAME ?= syva-dev
LIMA_CONFIG ?= ./lima/syva.yaml
REPO_DIR := $(shell pwd)

.PHONY: lima-up lima-shell lima-check lima-test lima-ebpf-build eval-build verify-runtime macos-check

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
	cargo run -p xtask -- verify-runtime

macos-check:
	cargo fmt --all -- --check
	cargo test -p syva-proto -p syva-ebpf-common -p syva-adapter-api
	cargo check -p syva-proto -p syva-ebpf-common -p syva-adapter-api -p syva-core-client
