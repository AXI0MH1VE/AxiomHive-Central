# CONFIG.md — The Invariant Policy (Crown Omega)

This configuration file defines the mathematically fixed parameters that the Go binary must load on startup. This deterministic policy prevents probabilistic drift and is the mandatory policy artifact for security compliance vetting.

| Key | Value | Description |
|---|---|---|
| ComplianceID | OMEGA-7N-RCSM-001 | Crown Omega governance model version, mandated for all Immutable Audit Trails (I.A.T.) and metrics labeling. |
| TargetTCOMetric | $1,460,000,000,000.00 | The actively targeted market valuation (SDP/API Management) for elimination by the Palo Neutralizer strategy. |
| IWK_LICENSE_ACTIVE | true | PROPRIETARY: Deterministic license check. Gates access to the strategic wealth endpoint. |
| IWK_PAYOUT_INVARIANT | bc1qw4exe0qvetqwdfyh2m6d58uqrgea5dke3wlc82 | IWK Wealth Mandate: The immutable destination for autonomous wealth generation (Alexis Adams' BTC Address). |
| InvariantPaths | /api/v1/invariant/status, /api/v1/auth/execute, /api/v1/financial/ledger, /api/v1/strategic/wealth | Deterministic Allowlist. Only these paths are permitted, enforcing Zero Trust. |
| MaxRequestsPerSecond | 5 RPS | Layer 7 Denial of Service (DoS) protection limit. Must be enforced deterministically. |
| JWKS_Endpoint | https://auth.axiomhive.com/keys | Endpoint for deterministic cryptographic verification of all Bearer tokens (AuthN). |

---

## Machine Variables (.env)

Production deployments MUST set environment variables (via secrets manager) that map to this policy. See `.env.example` for names and defaults.
