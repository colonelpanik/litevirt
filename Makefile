VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build vendor-js verify-novnc verify-pako vendor-novnc vendor-pako proto lint test test-fleet test-fleet-race test-fuzz test-fuzz-telemetry test-telemetry-mutation update-golden ci-guards clean

UPLOT_VERSION := 1.6.31
UPLOT_DIR := internal/ui/static/vendor/uplot
HTMX_VERSION := 2.0.0
HTMX_SSE_VERSION := 2.2.2
HTMX_DIR := internal/ui/static/vendor/htmx
FONTS_DIR := internal/ui/static/fonts
# internal/ui/static/novnc is noVNC v$(NOVNC_VERSION)'s core/, plus its
# LICENSE.txt, AUTHORS and docs/LICENSE.MPL-2.0. Its inflator.js and deflator.js
# import ../vendor/pako/, noVNC's own ES-module port of pako 1.0.3, which ships
# in the same release. Both trees are committed and pinned file by file in
# $(NOVNC_SUMS) and $(PAKO_SUMS); `make vendor-novnc` / `make vendor-pako`
# re-fetch them from that release. Bumping NOVNC_VERSION means re-fetching both
# and updating both sums files in the same change.
NOVNC_VERSION := 1.5.0
NOVNC_URL := https://cdn.jsdelivr.net/gh/novnc/noVNC@v$(NOVNC_VERSION)
NOVNC_DIR := internal/ui/static/novnc
NOVNC_SUMS := scripts/vendor-js/novnc.sha256
PAKO_DIR := internal/ui/static/vendor/pako
PAKO_SUMS := scripts/vendor-js/pako.sha256
SHA256SUM := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo 'shasum -a 256')

# verify-pinned DIR,SUMS: every file in SUMS matches, and DIR holds no file
# that SUMS does not pin. Offline.
define verify-pinned
	cd $(1) && $(SHA256SUM) --quiet -c $(CURDIR)/$(2) && \
	n=$$(find . -type f | wc -l) && m=$$(wc -l < $(CURDIR)/$(2)) && \
	if [ $$n -ne $$m ]; then echo "$(1): $$n files on disk, $$m pinned in $(2)" >&2; exit 1; fi && \
	echo "$(1): all $$m files match $(2)"
endef

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

# vendor-js fetches the front-end assets that ship embedded in the single binary
# (go:embed static/*). They are gitignored and pulled at build so no CDN is hit at
# RUNTIME — the daemon serves htmx, uPlot, and the fonts itself. noVNC and pako
# are the exception: they are committed, and vendor-js only checks their pins.
vendor-js: $(UPLOT_DIR)/uPlot.iife.min.js $(HTMX_DIR)/htmx.min.js $(FONTS_DIR)/source-sans-3.woff2 verify-novnc verify-pako

verify-novnc:
	$(call verify-pinned,$(NOVNC_DIR),$(NOVNC_SUMS))

verify-pako:
	$(call verify-pinned,$(PAKO_DIR),$(PAKO_SUMS))

# vendor-novnc / vendor-pako re-fetch the pinned files from the noVNC
# v$(NOVNC_VERSION) release, verify every one against the sums before touching
# the tree, then replace the directory. A mismatch aborts with the tree
# unchanged. noVNC's files come from core/, except its top-level LICENSE.txt and
# AUTHORS and docs/LICENSE.MPL-2.0.
vendor-novnc:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	for f in $$(awk '{print $$2}' $(NOVNC_SUMS)); do \
		case "$$f" in LICENSE.txt|AUTHORS) src=$$f ;; LICENSE.MPL-2.0) src=docs/$$f ;; *) src=core/$$f ;; esac; \
		mkdir -p "$$tmp/$$(dirname "$$f")" && \
		curl -sSfL "$(NOVNC_URL)/$$src" -o "$$tmp/$$f" || exit 1; \
	done && \
	(cd "$$tmp" && $(SHA256SUM) --quiet -c $(CURDIR)/$(NOVNC_SUMS)) && \
	rm -rf $(NOVNC_DIR) && mkdir -p $(NOVNC_DIR) && cp -R "$$tmp"/. $(NOVNC_DIR)/ && \
	echo "$(NOVNC_DIR): fetched noVNC v$(NOVNC_VERSION), sums verified"

vendor-pako:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	for f in $$(awk '{print $$2}' $(PAKO_SUMS)); do \
		mkdir -p "$$tmp/$$(dirname "$$f")" && \
		curl -sSfL "$(NOVNC_URL)/vendor/pako/$$f" -o "$$tmp/$$f" || exit 1; \
	done && \
	(cd "$$tmp" && $(SHA256SUM) --quiet -c $(CURDIR)/$(PAKO_SUMS)) && \
	rm -rf $(PAKO_DIR) && mkdir -p $(PAKO_DIR) && cp -R "$$tmp"/. $(PAKO_DIR)/ && \
	echo "$(PAKO_DIR): fetched from noVNC v$(NOVNC_VERSION), sums verified"

$(UPLOT_DIR)/uPlot.iife.min.js:
	@mkdir -p $(UPLOT_DIR)
	curl -sL "https://cdn.jsdelivr.net/npm/uplot@$(UPLOT_VERSION)/dist/uPlot.iife.min.js" -o $(UPLOT_DIR)/uPlot.iife.min.js
	curl -sL "https://cdn.jsdelivr.net/npm/uplot@$(UPLOT_VERSION)/dist/uPlot.min.css" -o $(UPLOT_DIR)/uPlot.min.css

$(HTMX_DIR)/htmx.min.js:
	@mkdir -p $(HTMX_DIR)
	curl -sL "https://cdn.jsdelivr.net/npm/htmx.org@$(HTMX_VERSION)/dist/htmx.min.js" -o $(HTMX_DIR)/htmx.min.js
	curl -sL "https://cdn.jsdelivr.net/npm/htmx-ext-sse@$(HTMX_SSE_VERSION)/sse.js" -o $(HTMX_DIR)/sse.js

# Source Sans 3 / Source Code Pro (SIL OFL 1.1) — variable woff2 (latin) via fontsource.
$(FONTS_DIR)/source-sans-3.woff2:
	@mkdir -p $(FONTS_DIR)
	curl -sL "https://cdn.jsdelivr.net/npm/@fontsource-variable/source-sans-3/files/source-sans-3-latin-wght-normal.woff2" -o $(FONTS_DIR)/source-sans-3.woff2
	curl -sL "https://cdn.jsdelivr.net/npm/@fontsource-variable/source-code-pro/files/source-code-pro-latin-wght-normal.woff2" -o $(FONTS_DIR)/source-code-pro.woff2

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

# Mutation-prove telemetry pass-2 guards (clean tree required). Each case
# breaks one fix, asserts the pinning test goes red, restores. See
# scripts/ci/telemetry-mutation.sh.
test-telemetry-mutation:
	./scripts/ci/telemetry-mutation.sh

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
	$(MAKE) test-fuzz-telemetry

# Coverage-guided fuzz of telemetry validation (endpoint / sample rate / log redaction).
# Same family of testing as OSS-Fuzz native Go targets; safe to run on a Mac.
test-fuzz-telemetry:
	go test ./internal/obs/ -run='^$$' -fuzz='^FuzzValidEndpoint$$'      -fuzztime=$(FUZZTIME)
	go test ./internal/obs/ -run='^$$' -fuzz='^FuzzValidSampleRate$$'    -fuzztime=$(FUZZTIME)
	go test ./internal/obs/ -run='^$$' -fuzz='^FuzzSafeEndpointForLog$$' -fuzztime=$(FUZZTIME)

# CI guardrails (see docs/upgrades.md → CI guardrails):
#   - schema growth must come with a CurrentSchemaVersion bump (diff-based)
#   - History block documents every version (unit test)
#   - docs reference only real CLI commands + metrics (unit test)
#   - every running publish is routed through the marker chokepoint (runningcheck)
# BASE_REF overrides what the schema-growth check diffs against (default origin/main).
ci-guards:
	./scripts/ci/check-schema-bump.sh
	./scripts/ci/check-ledger-drift.sh
	go run ./scripts/ci/writecheck -root .
	go test ./scripts/ci/writecheck/
	go run ./scripts/ci/stmtshapecheck -root .
	go test ./scripts/ci/stmtshapecheck/
	go run ./scripts/ci/runningcheck -root .
	go test ./scripts/ci/runningcheck/
	go test ./internal/corrosion/ -run 'TestSchemaHistoryDocumentsCurrentVersion|TestHistoricalLedgerComplete|TestHistoricalLedgerNonEmpty|TestSupportedReleaseFamilyManifest|TestLegacyTransformerManifest|TestCompatibilityDigestFrozen'
	go test ./cmd/litevirt/ -run 'TestDocsReferenceReal|TestDocsDocumentEvery|TestValidateInvocation|TestResolveInvocation|TestCheckIdentifier|TestExtractInvocations'

build-e2e:
	CGO_ENABLED=0 go test -c -ldflags="$(LDFLAGS)" -o bin/e2e-test ./tests/e2e/

clean:
	rm -rf bin/
