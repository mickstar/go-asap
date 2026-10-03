GOFLAGS ?= -mod=readonly -buildvcs=false
GOLANGCI_LINT ?= $(CURDIR)/bin/golangci-lint
MODULES := .

.PHONY: test lint go-fix-check golangci-lint unittest

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
