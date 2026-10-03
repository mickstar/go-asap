GOFLAGS ?= -mod=readonly -buildvcs=false
GOLANGCI_LINT ?= $(CURDIR)/bin/golangci-lint
MODULES := .

# Both tools import the retired jose dependency, which only runs on Go <= 1.26,
# so they are pinned to that toolchain and are not part of the shipped module.
TOOL_GO ?= go1.26.0
PARITYGEN := tools/paritygen
DIFFFUZZ := tools/difffuzz

# The pre-migration library. The fixture generator must record the asap*
# verdicts from THIS tree and not from the module under test, otherwise the
# fixtures are a self-portrait and cannot detect a mis-port.
ORACLE_COMMIT ?= 97f05bd

.PHONY: test lint go-fix-check golangci-lint unittest difffuzz parity-oracle parity-fixtures

test: lint unittest

lint: go-fix-check golangci-lint

go-fix-check:
	@for module in $(MODULES); do \
		output=$$(cd "$$module" && GOFLAGS='$(GOFLAGS)' go fix -diff ./...); status=$$?; \
		if [ -n "$$output" ]; then printf '%s\n' "$$output"; fi; \
		if [ $$status -ne 0 ] || [ -n "$$output" ]; then exit 1; fi; \
	done

golangci-lint:
	@set -e; for module in $(MODULES); do \
		(cd "$$module" && GOFLAGS='$(GOFLAGS)' "$(GOLANGCI_LINT)" run ./...); \
	done

unittest:
	@set -e; for module in $(MODULES); do \
		(cd "$$module" && GOFLAGS='$(GOFLAGS)' go test -v -cover -race ./...); \
	done

# Differential test: mints and verifies the same tokens with jose and with this
# module, then compares every verdict. Fails on any unexpected divergence.
difffuzz:
	@cd $(DIFFFUZZ) && GOFLAGS='$(GOFLAGS)' GOTOOLCHAIN=$(TOOL_GO) go test ./...

# Materialises the pre-migration library that the fixture generator links. It is
# derived from git history, so it is gitignored. Requires the commit below to be
# present: a shallow clone needs `git fetch --unshallow` first.
parity-oracle:
	@rm -rf $(PARITYGEN)/oracle && mkdir -p $(PARITYGEN)/oracle
	@git archive $(ORACLE_COMMIT) v2 | tar -x -C $(PARITYGEN)/oracle --strip-components=1

# Regenerates the frozen parity fixtures. Only needed when the oracle content
# changes deliberately; jose randomises ECDSA and RSA-PSS signatures and the
# validation fixtures are anchored at generation time, so the output is not
# byte-for-byte stable (the recorded verdicts are).
parity-fixtures: parity-oracle
	@cd $(PARITYGEN) && GOFLAGS='$(GOFLAGS)' GOTOOLCHAIN=$(TOOL_GO) go run . -out ../../testdata/parity
