# AILock DetEnforce Proxy — Production-Ready Deployment (ADVANCED PALO NEUTRALIZER)

**AXIOM HIVE** · Absolute Operational Integrity (AOI) via deterministic law.  
This repository contains the complete, auditable AILock system: the instrumented Go core, deterministic policy invariants, RBAC schema, and final documentation.

## Contents
- `CONFIG.md` — Crown Omega invariant policy (human-readable).
- `.env.example` — machine-readable env mapping for production secrets.
- `detenforce_financial_proxy.go` — single Go binary; deterministic allowlist; JWT/JWKS auth; global RPS limiter; Prometheus metrics; /health.
- `role_definitions.json` — deterministic RBAC schema.
- `go.mod` — module + pinned dependencies.
- `Dockerfile` — multi-stage build for tiny final image.
- `docker-compose.yml` — optional local orchestration.

## Build
```bash
# 1) Set environment (JWKS required)
cp .env.example .env
# edit .env with real JWKS endpoint and audience

# 2) Build
go mod tidy
go build -o detenforce detenforce_financial_proxy.go
```

## Run
```bash
export $(grep -v '^#' .env | xargs -d '
')
./detenforce
# or
LISTEN_ADDR=:8080 COMPLIANCE_ID=OMEGA-7N-RCSM-001 IWK_LICENSE_ACTIVE=true JWKS_ENDPOINT=https://auth.axiomhive.com/keys ALLOWED_AUDIENCE=axiomhive-clients MAX_RPS=5 ./detenforce
```

## Endpoints
- `GET /health` — JSON health status (no auth).
- `GET /metrics` — Prometheus metrics (no auth).
- `/*` — Protected by JWT/JWKS and allowlist:
  - `/api/v1/invariant/status`
  - `/api/v1/auth/execute`
  - `/api/v1/financial/ledger`
  - `/api/v1/strategic/wealth` (requires IWK license active)

## Deterministic Security Model
- **Deny by Default**: only allowlisted paths execute.
- **JWT/JWKS**: deterministic cryptographic verification of Bearer tokens.
- **Global RPS limiter**: fixed refill token-bucket (default 5 RPS).
- **IWK license gate**: explicitly controls wealth tactic endpoint.
- **Immutable Audit Trail**: structured JSON logs + Prometheus counters.

## Docker
```bash
# build
docker build -t axiomhive-ailock:latest .
# run
docker run -d -p 8080:8080 --env-file .env --name ailock axiomhive-ailock:latest
```

## License
Apache-2.0. Operator: Alexis Adams (Invariant Architect).
