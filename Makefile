LIMA_NAME ?= syva-dev
LIMA_CONFIG ?= ./lima/syva.yaml
REPO_DIR := $(shell pwd)

LIMA_SH = limactl shell $(LIMA_NAME) bash -lc
LIMA_SUDO = export PATH="$$HOME/.cargo/bin:$$PATH"; cd "$(REPO_DIR)"; sudo -E env PATH="$$PATH"

.PHONY: fmt lint test check precommit ci linux-bpf-check proto-check check-api-docs check-openapi check-release-docs check-ebpf-artifact-policy lima-up lima-shell lima-check lima-test lima-ebpf-build lima-bootstrap lima-deploy lima-verify-deployment lima-undeploy lima-reset lima-smoke eval-build verify-runtime verify-integration verify-container-integration verify-deployment macos-check

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

# Verify an ALREADY-DEPLOYED syva-core (does not start its own core).
# Needs SYVA_SOCKET (default /run/syva/syva-core.sock) + a container runtime.
# Run as: sudo -E make verify-deployment   (after `make lima-deploy`)
verify-deployment:
	env PATH="$$PATH:$$HOME/.cargo/bin:/home/$$SUDO_USER/.cargo/bin:/usr/local/cargo/bin" \
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
