// SPDX-License-Identifier: Apache-2.0
// Authentication — bearer token and API key authentication for MCP connections.
// Based on AegisGate Platform security patterns. Addresses auth, forgery, masquerading.

package mcpsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// p256 returns the P-256 curve. Centralised so that if we migrate to
// crypto/ecdh entirely we only change one place.
var p256 = elliptic.P256()

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// BearerToken: if set, all requests (except initialize) must include this token.
	// Passed during initialize via params.auth.token.
	BearerToken string

	// APIKeys: maps agent IDs to their API keys. If set, agents must authenticate
	// during initialize with their agent_id + api_key.
	APIKeys map[string]string // agentID → apiKey

	// SessionExpiry: how long authenticated sessions remain valid.
	SessionExpiry time.Duration

	// MaxAuthAttempts: max failed auth attempts before connection is blocked.
	MaxAuthAttempts int
}

// DefaultAuthConfig returns sensible defaults.
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		SessionExpiry:   1 * time.Hour,
		MaxAuthAttempts: 5,
	}
}

// AuthManager manages authentication state for MCP connections.
type AuthManager struct {
	config   *AuthConfig
	mu       sync.RWMutex
	authed   map[string]*authState // connID → auth state
	attempts map[string]int        // connID → failed attempts
	// Global rate limiting: tracks total failed attempts across all
	// connections within a sliding window. Prevents distributed brute force.
	globalAttempts    int
	globalWindowStart time.Time
	// OnAuthSuccess is called after successful authentication.
	// Returns the RBAC session ID (empty if no session created).
	OnAuthSuccess func(connID, agentID string) string
}

type authState struct {
	AgentID   string
	AuthedAt  time.Time
	ExpiresAt time.Time
}

// NewAuthManager creates a new auth manager.
func NewAuthManager(cfg *AuthConfig) *AuthManager {
	if cfg == nil {
		cfg = DefaultAuthConfig()
	}
	return &AuthManager{
		config:   cfg,
		authed:   make(map[string]*authState),
		attempts: make(map[string]int),
	}
}

// HandleInitialize processes the initialize request to authenticate the connection.
// Returns true if authentication succeeded (or is not required).
func (a *AuthManager) HandleInitialize(connID string, params json.RawMessage) (string, bool) {
	if a.config.BearerToken == "" && len(a.config.APIKeys) == 0 {
		// No auth required
		return "", true
	}

	// Parse auth from initialize params
	var initParams struct {
		Auth struct {
			Token   string `json:"token"`
			AgentID string `json:"agentId"`
			APIKey  string `json:"apiKey"`
		} `json:"auth"`
	}
	if params != nil {
		json.Unmarshal(params, &initParams)
	}

	// Check bearer token
	if a.config.BearerToken != "" {
		if subtle.ConstantTimeCompare([]byte(initParams.Auth.Token), []byte(a.config.BearerToken)) == 1 {
			agentID := initParams.Auth.AgentID
			if agentID == "" {
				agentID = "authenticated"
			}
			a.markAuthed(connID, agentID)
			slog.Info("auth success: bearer token", "conn_id", connID, "agent_id", agentID)
			return agentID, true
		}
	}

	// Check API key
	if len(a.config.APIKeys) > 0 && initParams.Auth.AgentID != "" {
		expectedKey, ok := a.config.APIKeys[initParams.Auth.AgentID]
		if ok && subtle.ConstantTimeCompare([]byte(initParams.Auth.APIKey), []byte(expectedKey)) == 1 {
			a.markAuthed(connID, initParams.Auth.AgentID)
			slog.Info("auth success: API key", "conn_id", connID, "agent_id", initParams.Auth.AgentID)
			return initParams.Auth.AgentID, true
		}
	}

	// Auth failed
	a.mu.Lock()
	a.attempts[connID]++
	attempts := a.attempts[connID]

	// Global rate limiting: track total failures across all connections
	// within a sliding 1-minute window. If the global threshold is exceeded,
	// reject all new auth attempts (mitigates distributed brute force).
	now := time.Now()
	if now.Sub(a.globalWindowStart) > time.Minute {
		a.globalAttempts = 0
		a.globalWindowStart = now
	}
	a.globalAttempts++
	globalExceeded := a.globalAttempts > 100 // 100 failures/min global threshold

	a.mu.Unlock()

	if globalExceeded {
		slog.Warn("global auth rate limit exceeded",
			"conn_id", connID, "global_attempts", a.globalAttempts,
			"window", "1m")
	}
	slog.Warn("auth failed", "conn_id", connID, "attempts", attempts,
		"global_attempts", a.globalAttempts)
	return "", false
}

// IsAuthenticated checks if a connection is authenticated.
func (a *AuthManager) IsAuthenticated(connID string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	state, ok := a.authed[connID]
	if !ok {
		return false
	}
	return time.Now().Before(state.ExpiresAt)
}

// GetAgentID returns the authenticated agent ID for a connection.
func (a *AuthManager) GetAgentID(connID string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	state, ok := a.authed[connID]
	if !ok {
		return ""
	}
	return state.AgentID
}

// IsGlobalRateLimited returns true if the global auth failure threshold
// has been exceeded within the current window. This prevents distributed
// brute force attacks that rotate connections to bypass per-connection limits.
func (a *AuthManager) IsGlobalRateLimited() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.globalWindowStart.IsZero() {
		return false
	}
	// Window has expired — not rate limited
	if time.Since(a.globalWindowStart) > time.Minute {
		return false
	}
	return a.globalAttempts > 100
}

// IsBlocked returns true if a connection has exceeded max auth attempts.
func (a *AuthManager) IsBlocked(connID string) bool {
	if a.config.MaxAuthAttempts <= 0 {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.attempts[connID] >= a.config.MaxAuthAttempts
}

// CleanupConn removes auth state for a closed connection.
func (a *AuthManager) CleanupConn(connID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.authed, connID)
	delete(a.attempts, connID)
}

func (a *AuthManager) markAuthed(connID, agentID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.authed[connID] = &authState{
		AgentID:   agentID,
		AuthedAt:  now,
		ExpiresAt: now.Add(a.config.SessionExpiry),
	}
	delete(a.attempts, connID)
}

// ============================================================
// Signature Verification (anti-forgery)
// ============================================================

// SignatureVerifier verifies MCP message signatures using ECDSA P-256.
type SignatureVerifier struct {
	trustedKeys map[string][]byte // keyID → public key bytes (SEC1)
	mu          sync.RWMutex
	enabled     bool
}

// NewSignatureVerifier creates a new signature verifier.
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		trustedKeys: make(map[string][]byte),
		enabled:     true,
	}
}

// AddTrustedKey adds a trusted public key for signature verification.
func (v *SignatureVerifier) AddTrustedKey(keyID string, pubKeySEC1 []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedKeys[keyID] = pubKeySEC1
}

// VerifyRequest verifies the ECDSA P-256 signature on an MCP request.
// The signature covers the canonical JSON of the request with the
// Signature and KeyID fields zeroed out. This prevents tampering with
// the request body after signing.
//
// If signature verification is disabled, or if no KeyID/Signature is
// present on the request, verification is skipped (returns nil). This
// allows the server to interoperate with unsigned clients while
// enforcing signatures for clients that provide them.
func (v *SignatureVerifier) VerifyRequest(req *JSONRPCRequest, connAddr net.Addr) error {
	if !v.Enabled() {
		return nil
	}
	if req.KeyID == "" || req.Signature == "" {
		// No signature present — skip verification.
		// The AuthMiddleware handles access control separately.
		return nil
	}

	v.mu.RLock()
	pubKeyBytes, ok := v.trustedKeys[req.KeyID]
	v.mu.RUnlock()
	if !ok {
		slog.Warn("signature verification failed: unknown key", "keyId", req.KeyID, "connAddr", connAddr)
		return fmt.Errorf("unknown signing key: %s", req.KeyID)
	}

	pubKey, err := publicKeyFromSEC1(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid trusted key %s: %w", req.KeyID, err)
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		slog.Warn("signature verification failed: invalid hex", "keyId", req.KeyID, "connAddr", connAddr)
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	canonical, err := canonicalRequestForSigning(req)
	if err != nil {
		return fmt.Errorf("canonicalize request: %w", err)
	}
	hash := sha256.Sum256(canonical)

	if !ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
		slog.Warn("signature verification failed: invalid signature",
			"keyId", req.KeyID, "connAddr", connAddr,
			"method", req.Method)
		return fmt.Errorf("signature verification failed for key %s", req.KeyID)
	}

	slog.Info("signature verified", "keyId", req.KeyID, "method", req.Method, "connAddr", connAddr)
	return nil
}

// Enabled returns whether signature verification is active.
func (v *SignatureVerifier) Enabled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.enabled
}

// SetEnabled enables or disables signature verification.
func (v *SignatureVerifier) SetEnabled(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = enabled
}

// TrustedKeyCount returns the number of trusted keys.
func (v *SignatureVerifier) TrustedKeyCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.trustedKeys)
}

// AuthMiddleware wraps a HandlerFunc with authentication checks.
func (a *AuthManager) AuthMiddleware(inner HandlerFunc) HandlerFunc {
	return func(conn *Connection, req *JSONRPCRequest) *JSONRPCResponse {
		// Initialize is always allowed (it's where auth happens)
		if req.Method == "initialize" {
			// Check global rate limit before attempting auth
			if a.IsGlobalRateLimited() {
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Error: &JSONRPCError{Code: ErrorRateLimited, Message: "global auth rate limit exceeded — try again later"},
				}
			}
			agentID, ok := a.HandleInitialize(conn.ID, req.Params)
			if !ok {
				if a.IsBlocked(conn.ID) {
					return &JSONRPCResponse{
						JSONRPC: JSONRPCVersion, ID: req.ID,
						Error: &JSONRPCError{Code: ErrorForbidden, Message: "too many failed auth attempts"},
					}
				}
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Error: &JSONRPCError{Code: ErrorUnauthorized, Message: "authentication failed"},
				}
			}
			// Set agent ID on connection
			conn.mu.Lock()
			conn.AgentID = agentID
			if conn.Session != nil {
				conn.Session.AgentID = agentID
			}
			conn.mu.Unlock()

			// Create RBAC session if callback is configured
			if a.OnAuthSuccess != nil {
				if rbacSessionID := a.OnAuthSuccess(conn.ID, agentID); rbacSessionID != "" {
					conn.mu.Lock()
					if conn.Session != nil {
						conn.Session.ID = rbacSessionID
					}
					conn.mu.Unlock()
				}
			}

			return inner(conn, req)
		}

		// Check if auth is required
		if a.config.BearerToken != "" || len(a.config.APIKeys) > 0 {
			if !a.IsAuthenticated(conn.ID) {
				return &JSONRPCResponse{
					JSONRPC: JSONRPCVersion, ID: req.ID,
					Error: &JSONRPCError{Code: ErrorUnauthorized, Message: "not authenticated — send initialize with auth credentials"},
				}
			}
		}

		return inner(conn, req)
	}
}

// ============================================================
// Signing helpers (ECDSA P-256)
// ============================================================

// publicKeyFromSEC1 decodes an SEC 1 uncompressed ECDSA public key
// (the format produced by elliptic.Marshal for P-256). Returns the
// *ecdsa.PublicKey or an error if the bytes are malformed.
func publicKeyFromSEC1(sec1 []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(p256, sec1)
	if x == nil {
		return nil, fmt.Errorf("invalid SEC 1 bytes for P-256")
	}
	return &ecdsa.PublicKey{Curve: p256, X: x, Y: y}, nil
}

// canonicalRequestForSigning produces a canonical JSON representation
// of the request with the Signature and KeyID fields zeroed out. This
// is the byte sequence that the client must sign and the server must
// verify. The canonical form ensures that semantically identical
// requests produce identical signatures regardless of key ordering
// or whitespace in the original JSON.
func canonicalRequestForSigning(req *JSONRPCRequest) ([]byte, error) {
	// Make a shallow copy with signature fields zeroed
	signed := *req
	signed.KeyID = ""
	signed.Signature = ""

	// Marshal with sorted keys for canonical form
	data, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}

	// Re-marshal through a generic decode/encode to normalize
	// any nested key ordering in Params
	var generic interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// SignRequest signs a JSONRPCRequest with an ECDSA P-256 private key.
// This is the client-side helper that produces the KeyID and Signature
// fields. The server uses VerifyRequest to check them.
//
// keyID identifies the key pair to the server (must match a trusted key).
// privKey is the ECDSA P-256 private key.
//
// The signature covers canonicalRequestForSigning(req) hashed with
// SHA-256, and is encoded as ASN.1 DER (the format ecdsa.VerifyASN1
// expects). The Signature field on the request is set to the hex-
// encoded signature, and KeyID is set to keyID.
func SignRequest(req *JSONRPCRequest, keyID string, privKey *ecdsa.PrivateKey) error {
	if keyID == "" {
		return fmt.Errorf("keyID is required")
	}
	if privKey == nil {
		return fmt.Errorf("private key is required")
	}
	if privKey.Curve != p256 {
		return fmt.Errorf("private key must be P-256, got %s", privKey.Curve.Params().Name)
	}

	// Zero signature fields before canonicalizing
	req.KeyID = ""
	req.Signature = ""

	canonical, err := canonicalRequestForSigning(req)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	hash := sha256.Sum256(canonical)

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	req.KeyID = keyID
	req.Signature = hex.EncodeToString(sig)
	return nil
}
