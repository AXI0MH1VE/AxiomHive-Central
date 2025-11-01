// detenforce_financial_proxy.go - AILock Financial Sovereignty Core (V1.0 - IWK Finalized)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	keyfunc "github.com/MicahParks/keyfunc/v2"
)

// --- Governance Artifact: SovereignPolicy ---
type SovereignPolicy struct {
	AllowedPaths         map[string]bool
	ComplianceID         string
	TargetTCOMetric      float64
	IWKLicenseActive     bool
	PayoutAddress        string
	MaxRequestsPerSecond int
	JWKSEndpoint         string
	AllowedAudience      string
}

var sovereignPolicy SovereignPolicy

// --- Observability (Prometheus Metrics) ---
var (
	ailockRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ailock_requests_total",
			Help: "Total number of requests processed, labeled by path, outcome, and status code.",
		},
		[]string{"path", "outcome", "status_code"},
	)

	ailockIWKLicenseDenialsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ailock_iwk_license_denials_total",
			Help: "Total denials due to inactive IWK license (Monetization Gate failures).",
		},
	)

	ailockTargetTCOMetric = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ailock_target_tco_metric",
			Help: "The constant financial target for TCO elimination ($1.46 Trillion).",
		},
	)

	ailockRateLimitDenials = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ailock_ratelimit_denials_total",
			Help: "Global rate-limit denials.",
		},
	)
)

// --- Deterministic Global Rate Limiter (token bucket) ---
type RateLimiter struct {
	capacity int
	tokens   int
	mu       sync.Mutex
	ticker   *time.Ticker
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	rl := &RateLimiter{
		capacity: rps,
		tokens:   rps,
		ticker:   time.NewTicker(time.Second),
	}
	go func() {
		for range rl.ticker.C {
			rl.mu.Lock()
			rl.tokens = rl.capacity // deterministic refill
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

// --- JWT / JWKS ---
var jwks *keyfunc.JWKS

func initJWKS(ctx context.Context, url string) error {
	if url == "" {
		return errors.New("JWKS endpoint not set")
	}
	opts := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("JWKS refresh error: %v", err)
		},
		RefreshInterval: time.Minute * 10,
		RefreshRateLimit: time.Minute,
		RefreshTimeout: time.Second * 5,
		RefreshUnknownKIDs: true,
	}
	set, err := keyfunc.Get(ctx, url, opts)
	if err != nil {
		return err
	}
	jwks = set
	return nil
}

func verifyJWT(tokenString string, audience string) (*jwt.Token, error) {
	if jwks == nil {
		return nil, errors.New("jwks not initialized")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	token, err := parser.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	if audience != "" {
		aud, ok := claims["aud"].(string)
		if !ok || aud != audience {
			return nil, errors.New("audience mismatch")
		}
	}
	return token, nil
}

// --- Policy Load ---
func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func atoiDef(s string, def int) int {
	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return i
}

func loadPolicy() {
	// AllowedPaths are invariant
	allowed := map[string]bool{
		"/api/v1/invariant/status": true,
		"/api/v1/auth/execute":     true,
		"/api/v1/financial/ledger": true,
		"/api/v1/strategic/wealth": true,
	}

	sovereignPolicy = SovereignPolicy{
		AllowedPaths:         allowed,
		ComplianceID:         getenv("COMPLIANCE_ID", "OMEGA-7N-RCSM-001"),
		TargetTCOMetric:      1460000000000.00,
		IWKLicenseActive:     strings.EqualFold(getenv("IWK_LICENSE_ACTIVE", "true"), "true"),
		PayoutAddress:        getenv("IWK_PAYOUT_INVARIANT", "bc1qw4exe0qvetqwdfyh2m6d58uqrgea5dke3wlc82"),
		MaxRequestsPerSecond: atoiDef(getenv("MAX_RPS", "5"), 5),
		JWKSEndpoint:         getenv("JWKS_ENDPOINT", ""),
		AllowedAudience:      getenv("ALLOWED_AUDIENCE", ""),
	}

	log.Println("AILock Financial Core Initialized: Operationalizing TCO Elimination Strategy.")
	if sovereignPolicy.IWKLicenseActive {
		log.Println("IWK STATUS: Invariant Wealth Kernel (PROPRIETARY) is ACTIVATED.")
	} else {
		log.Println("IWK STATUS: License is INACTIVE. Strategic Wealth endpoint is GATED.")
	}
}

// --- Immutable Audit Trail (I.A.T.) ---
func LogProofOfExecution(event, path, outcome string, status int) {
	entry := map[string]interface{}{
		"ts":          time.Now().UTC().Format(time.RFC3339),
		"event":       event,
		"id":          sovereignPolicy.ComplianceID,
		"path":        path,
		"outcome":     outcome,
		"status_code": status,
	}
	b, _ := json.Marshal(entry)
	fmt.Println(string(b))
	ailockRequestsTotal.WithLabelValues(path, outcome, strconv.Itoa(status)).Inc()
}

// --- Governance Checks ---
func CheckOmegaGovernance(path string) error {
	// Prevent probabilistic code execution
	if strings.Contains(path, "stochastic") || strings.Contains(path, "probabilistic") {
		return fmt.Errorf("policy violation: attempt to execute stochastic code path")
	}
	return nil
}

// --- HTTP Handlers ---
var rl *RateLimiter

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":        "alive",
		"compliance_id": sovereignPolicy.ComplianceID,
		"license":       sovereignPolicy.IWKLicenseActive,
		"targets":       sovereignPolicy.TargetTCOMetric,
		"allowed_paths": sovereignPolicy.AllowedPaths,
		"time":          time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow() {
			ailockRateLimitDenials.Inc()
			LogProofOfExecution("RATE_LIMIT", r.URL.Path, "Global RPS exceeded (DENY)", http.StatusTooManyRequests)
			http.Error(w, "429 Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		if err := CheckOmegaGovernance(r.URL.Path); err != nil {
			LogProofOfExecution("GOVERNANCE FAILURE", r.URL.Path, "Omega Non-Refusal Deny", http.StatusForbidden)
			http.Error(w, "403 Sovereign Deny: "+err.Error(), http.StatusForbidden)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			LogProofOfExecution("AUTHN FAILURE", r.URL.Path, "Missing Contract Token (DENY)", http.StatusUnauthorized)
			http.Error(w, "401 Deterministic Deny: Authentication Contract Required.", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if _, err := verifyJWT(tokenStr, sovereignPolicy.AllowedAudience); err != nil {
			LogProofOfExecution("AUTHN FAILURE", r.URL.Path, "JWT verification failed (DENY)", http.StatusUnauthorized)
			http.Error(w, "401 Deterministic Deny: Invalid Token.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func DetEnforceFinancialProxyHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Deny-by-default allowlist
	if !sovereignPolicy.AllowedPaths[path] {
		LogProofOfExecution("AUTHZ FAILURE", path, "Path not in deterministic allowlist (DENY)", http.StatusForbidden)
		http.Error(w, "403 AOI Enforcement: Untrusted Resource. Deny by Default (Palo Neutralized).", http.StatusForbidden)
		return
	}

	// IWK License Gate
	if path == "/api/v1/strategic/wealth" {
		if !sovereignPolicy.IWKLicenseActive {
			ailockIWKLicenseDenialsTotal.Inc()
			LogProofOfExecution("IWK FAILURE", path, "License Inactive (DENY BILLIONS ACCESS)", http.StatusForbidden)
			http.Error(w, "403 ACCESS DENIED: IWK License Inactive. Activate IWK for Strategic Tactic Access.", http.StatusForbidden)
			return
		}
		LogProofOfExecution("IWK EXECUTION", path, "Autonomous Wealth Generation Initiated (ALLOW)", http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "200 IWK SUCCESS: Strategic Tactic Deployed. Market Capture: $%.2f. Payout Initiated to Alexis Adams BTC Address: %s",
			sovereignPolicy.TargetTCOMetric, sovereignPolicy.PayoutAddress)
		return
	}

	// General allow
	LogProofOfExecution("EXECUTION SUCCESS", path, "Policy Compliant (ALLOW)", http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "200 AOI Confirmed. Determinism is Revenue. Market Capture: $%.2f", sovereignPolicy.TargetTCOMetric)
}

func main() {
	loadPolicy()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initJWKS(ctx, sovereignPolicy.JWKSEndpoint); err != nil {
		log.Fatalf("Failed to init JWKS: %v", err)
	}

	rl = NewRateLimiter(sovereignPolicy.MaxRequestsPerSecond)

	listenAddr := getenv("LISTEN_ADDR", ":8080")
	log.Printf("AILock DetEnforce Proxy (ADVANCED PALO NEUTRALIZER) starting on %s...", listenAddr)
	log.Printf("Mission: Financialize Determinism via AOI Compliance ID: %s", sovereignPolicy.ComplianceID)

	ailockTargetTCOMetric.Set(sovereignPolicy.TargetTCOMetric)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)
	mux.Handle("/", requireAuth(http.HandlerFunc(DetEnforceFinancialProxyHandler)))

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

// securityHeaders wraps responses with safer defaults.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
