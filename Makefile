VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build proto lint test test-fleet test-fleet-race test-fuzz update-golden ci-guards clean

UPLOT_VERSION := 1.6.31
UPLOT_DIR := internal/ui/static/vendor/uplot

all: proto vendor-js build

build: vendor-js build-litevirt

# build-litevirt produces the single combined binary. `litevirt daemon` runs
# the server; `litevirt <cmd>` is the CLI; `litevirt schema-migrate <db>`
# pre-stages schema; `litevirt gitops --repo <url>` runs the GitOps reconcile
# loop (folded in from the former standalone litevirt-gitops binary). A
# convenience `bin/lv` symlink keeps muscle memory.
build-litevirt:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/litevirt ./cmd/litevirt
	ln -sf litevirt bin/lv

vendor-js: $(UPLOT_DIR)/uPlot.iife.min.js

$(UPLOT_DIR)/uPlot.iife.min.js:
	@mkdir -p $(UPLOT_DIR)
	curl -sL "https://cdn.jsdelivr.net/npm/uplot@$(UPLOT_VERSION)/dist/uPlot.iife.min.js" -o $(UPLOT_DIR)/uPlot.iife.min.js
	curl -sL "https://cdn.jsdelivr.net/npm/uplot@$(UPLOT_VERSION)/dist/uPlot.min.css" -o $(UPLOT_DIR)/uPlot.min.css

proto:
	buf generate

lint:
	golangci-lint run ./...

test:
	go test ./...

# Run the in-process fleet integration suite (tests/fleet/). Sub-second
# without -race; ~10s with -race because the goroutine instrumentation
# hits real gRPC + real CRDT replication in tight loops.
test-fleet:
	go test ./tests/fleet/ -count=1 -v

test-fleet-race:
	go test ./tests/fleet/ -count=1 -race

# Refresh golden files in place after an intentional rendering change.
# Inspect the diff before committing.
update-golden:
	go test ./internal/firewall/ -run TestRenderGolden -update
	go test ./internal/libvirt/ -run TestGenerateDomainXMLGolden -update
	go test ./internal/lb/ -run TestLBRenderGolden -update
	go test ./internal/grpcapi/ -run TestBuildIsolatedNetworkConfigGolden -update

# Run each fuzz target for FUZZTIME (default 30s). Override with
# `make test-fuzz FUZZTIME=5m` for nightly runs.
FUZZTIME ?= 30s
test-fuzz:
	go test ./internal/compose/  -run='^$$' -fuzz='^FuzzParseBytes$$'        -fuzztime=$(FUZZTIME)
	go test ./internal/hlc/      -run='^$$' -fuzz='^FuzzParse$$'             -fuzztime=$(FUZZTIME)
	go test ./internal/firewall/ -run='^$$' -fuzz='^FuzzFromCorrosionRule$$' -fuzztime=$(FUZZTIME)
	go test ./internal/firewall/ -run='^$$' -fuzz='^FuzzRender$$'            -fuzztime=$(FUZZTIME)
	go test ./internal/lb/       -run='^$$' -fuzz='^FuzzParseVIP$$'          -fuzztime=$(FUZZTIME)

# CI guardrails (see docs/upgrades.md → CI guardrails):
#   - schema growth must come with a CurrentSchemaVersion bump (diff-based)
#   - History block documents every version (unit test)
#   - docs reference only real CLI commands + metrics (unit test)
# BASE_REF overrides what the schema-growth check diffs against (default origin/main).
ci-guards:
	./scripts/ci/check-schema-bump.sh
	go test ./internal/corrosion/ -run TestSchemaHistoryDocumentsCurrentVersion
	go test ./cmd/litevirt/ -run 'TestDocsReferenceReal|TestValidateInvocation|TestCheckIdentifier|TestExtractInvocations'

build-e2e:
	CGO_ENABLED=0 go test -c -ldflags="$(LDFLAGS)" -o bin/e2e-test ./tests/e2e/

clean:
	rm -rf bin/
