# Upstream Reference

## Official HQC

| Field | Value |
|-------|-------|
| Algorithm | HQC (Hamming Quasi-Cyclic) |
| Source | Official HQC reference implementation |
| Repository | https://gitlab.com/pqc-hqc/hqc/ |
| Tag | v5.0.0 (2025-08-22) |
| NIST status | Selected for standardization (FIPS 207 pending) |

go-hqc targets the v5.0.0 specification parameters.

## Tracking

Automated weekly check via GitHub Actions (`.github/workflows/check-upstream.yml`).
Opens an issue if new tags appear beyond v5.0.0.

Manual check:

```sh
go run tools/check-upstream/main.go
```
