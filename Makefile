# ReFineID Unix Makefile

CARGO ?= cargo

.PHONY: default help build check clean

default: build

help:
	@echo "ReFineID for Unix."
	@echo "  make build   -> release build of the whole workspace"
	@echo "  make check   -> build + test + clippy + fmt gate"
	@echo "  make clean   -> remove build artifacts"
	@echo ""
	@echo "NixOS users: see doc/install-nixos.md (nix build / NixOS module)."

build:
	$(CARGO) build --release --workspace
	@echo ""
	@echo "built:"
	@echo "  target/release/refineid                 (CLI)"
	@echo "  target/release/refineid-card-manager    (GUI)"
	@echo "  target/release/librefineid_pkcs11.so    (Firefox/NSS card login)"

check:
	./script/check.sh

clean:
	$(CARGO) clean
