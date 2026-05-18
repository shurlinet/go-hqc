.PHONY: test bench fuzz fuzz-long lint
.PHONY: accumulated-100 accumulated-1k accumulated-10k accumulated-100k accumulated-1m

# Standard test suite (KAT + property + accumulated-100 + examples).
test:
	go test -race -count=1 ./...

# Benchmarks for all 3 parameter sets.
bench:
	go test -bench=. -benchmem -run=^$$ ./...

# Fuzz tests (30s minimum for pre-release gate).
fuzz:
	go test -fuzz=FuzzDecapsulate128 -fuzztime=30s
	go test -fuzz=FuzzKeyRoundTrip128 -fuzztime=30s

# Extended fuzz (5 minutes per target).
fuzz-long:
	go test -fuzz=FuzzDecapsulate128 -fuzztime=5m
	go test -fuzz=FuzzKeyRoundTrip128 -fuzztime=5m

# Static analysis.
lint:
	go vet ./...
	staticcheck ./...

# Accumulated hash verification tiers.
# Each tier verifies N complete KEM cycles (keygen + encaps + decaps) against
# SHAKE128 accumulated hashes from v5.0.0 C. All 3 param sets run sequentially.
accumulated-100: # ~10s total (runs in make test)
	go test -race -count=1 -run=TestAccumulated ./...

accumulated-1k: # ~2 min total
	GOHQC_ACCUMULATED=1000 go test -count=1 -run=TestAccumulated -v ./...

accumulated-10k: # ~17 min total
	GOHQC_ACCUMULATED=10000 go test -count=1 -run=TestAccumulated -v ./...

accumulated-100k: # ~2.5 hours total (pre-release gate)
	GOHQC_ACCUMULATED=100000 go test -count=1 -run=TestAccumulated -v -timeout=4h ./...

accumulated-1m: # ~28 hours total (auditor reference verification)
	GOHQC_ACCUMULATED=1000000 go test -count=1 -run=TestAccumulated -v -timeout=48h ./...
