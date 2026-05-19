# Upstream Reference

## Official HQC

| Field | Value |
|-------|-------|
| Algorithm | HQC (Hamming Quasi-Cyclic) |
| Source | Official HQC reference implementation |
| Repository | https://gitlab.com/pqc-hqc/hqc/ |
| Branch | next-release |
| Commit | `161cd4fdf6b4a5198cf40b3a1243f9f27f13e03d` (2026-02-13) |
| Base tag | v5.0.0 (2025-08-22) + 3 commits |
| NIST status | Selected for standardization (FIPS 207 pending) |

go-hqc targets the v5.0.0 specification parameters with the `next-release`
branch sampling update (PR #15: sampler1 LE byte order, per-candidate XOF reads,
XOF alignment removal). KAT vectors and all test data are generated from commit
`161cd4f`. When the next official tag is published, go-hqc will update to match.

## Tracking

Automated weekly check via GitHub Actions (`.github/workflows/check-upstream.yml`).
Opens an issue if new tags appear beyond v5.0.0.

Manual check:

```sh
go run tools/check-upstream/main.go
```
