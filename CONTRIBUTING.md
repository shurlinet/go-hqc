# Contributing to go-hqc

## Versioning Policy

go-hqc follows strict [semantic versioning](https://semver.org/).

### What constitutes each version bump

**PATCH** (v0.1.0 -> v0.1.1):
- Bug fixes that do NOT change KEM output (constant-time improvements, doc
  fixes, CI updates, test additions, dependency bumps)
- The KAT vectors must produce identical output before and after the patch

**MINOR** (v0.1.x -> v0.2.0):
- Any change that alters KEM output (keygen, encapsulate, or decapsulate
  produces different bytes for the same input)
- API additions (new functions, new types)
- Specification version changes (e.g., updating from v5.0.0 to
  FIPS 207)

**MAJOR** (v0.x -> v1.0.0):
- Reserved for the first FIPS 207-compliant release
- v1.0.0 ships only after FIPS 207 is published and the implementation
  matches the final standard

### Why this matters

Go's minimum version selection (MVS) resolves transitive dependencies to the
highest compatible version. If a consumer imports go-hqc v0.1.0 and another
dependency imports go-hqc v0.1.1, the consumer gets v0.1.1. Strict adherence
to the rules above ensures that PATCH bumps never change cryptographic output.

## KAT Gate

All KAT vectors (60 total: 10 keygen + 10 encaps per param set, 3
param sets) must pass byte-for-byte before any commit is merged. This is
non-negotiable.

## Testing Requirements

Before submitting changes:

```sh
go test -race -count=1 ./...
go test -fuzz=FuzzDecapsulate128 -fuzztime=30s
go test -fuzz=FuzzKeyRoundTrip128 -fuzztime=30s
staticcheck ./...
```

All must pass clean.

## Security

If you find a security vulnerability, do NOT open a public issue. Contact the
maintainer directly.
