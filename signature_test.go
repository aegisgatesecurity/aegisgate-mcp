// SPDX-License-Identifier: Apache-2.0
// Signature verifier tests — ECDSA P-256 signing and verification.

package mcpsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

// generateTestKey generates an ECDSA P-256 key pair for testing.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// publicKeyToSEC1 encodes a P-256 public key as SEC 1 uncompressed bytes.
func publicKeyToSEC1(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
}

// --- SignatureVerifier ---

func TestSignatureVerifierAddTrustedKey(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	v.AddTrustedKey("key-1", pubBytes)
	if v.TrustedKeyCount() != 1 {
		t.Errorf("TrustedKeyCount = %d, want 1", v.TrustedKeyCount())
	}
}

func TestSignatureVerifierEnabledDefault(t *testing.T) {
	v := NewSignatureVerifier()
	if !v.Enabled() {
		t.Error("should be enabled by default")
	}
}

func TestSignatureVerifierSetEnabled(t *testing.T) {
	v := NewSignatureVerifier()
	v.SetEnabled(false)
	if v.Enabled() {
		t.Error("should be disabled after SetEnabled(false)")
	}
	v.SetEnabled(true)
	if !v.Enabled() {
		t.Error("should be enabled after SetEnabled(true)")
	}
}

func TestSignatureVerifierVerifyValidSignature(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	v.AddTrustedKey("test-key", pubBytes)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		Params:  []byte(`{"name":"get_uptime"}`),
		ID:      1,
	}

	// Sign the request
	if err := SignRequest(req, "test-key", privKey); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Verify
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	if err := v.VerifyRequest(req, addr); err != nil {
		t.Errorf("VerifyRequest failed: %v", err)
	}
}

func TestSignatureVerifierVerifyInvalidSignature(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	v.AddTrustedKey("test-key", pubBytes)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "tools/call",
		Params:  []byte(`{"name":"get_uptime"}`),
		ID:      1,
	}

	// Sign the request
	SignRequest(req, "test-key", privKey)

	// Tamper with the request after signing
	req.Params = []byte(`{"name":"shell_command"}`)

	// Verification should fail
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	err := v.VerifyRequest(req, addr)
	if err == nil {
		t.Error("VerifyRequest should fail for tampered request")
	}
}

func TestSignatureVerifierUnknownKeyID(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)

	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      1,
	}
	SignRequest(req, "unknown-key", privKey)

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	err := v.VerifyRequest(req, addr)
	if err == nil {
		t.Error("should fail for unknown key ID")
	}
	if !contains(err.Error(), "unknown signing key") {
		t.Errorf("error should mention 'unknown signing key': %s", err.Error())
	}
}

func TestSignatureVerifierNoSignature(t *testing.T) {
	v := NewSignatureVerifier()
	req := &JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		Method:  "ping",
		ID:      1,
		// No KeyID, no Signature
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	if err := v.VerifyRequest(req, addr); err != nil {
		t.Errorf("should pass for unsigned request: %v", err)
	}
}

func TestSignatureVerifierDisabled(t *testing.T) {
	v := NewSignatureVerifier()
	v.SetEnabled(false)

	req := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "ping",
		ID:        1,
		KeyID:     "some-key",
		Signature: "deadbeef",
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	if err := v.VerifyRequest(req, addr); err != nil {
		t.Errorf("disabled verifier should not check: %v", err)
	}
}

func TestSignatureVerifierInvalidHexSignature(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	v.AddTrustedKey("test-key", pubBytes)

	req := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "ping",
		ID:        1,
		KeyID:     "test-key",
		Signature: "not-valid-hex!!!",
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	err := v.VerifyRequest(req, addr)
	if err == nil {
		t.Error("should fail for invalid hex signature")
	}
	if !contains(err.Error(), "invalid signature encoding") {
		t.Errorf("error should mention encoding: %s", err.Error())
	}
}

func TestSignatureVerifierInvalidTrustedKey(t *testing.T) {
	v := NewSignatureVerifier()
	// Add an invalid key (not valid SEC 1)
	v.AddTrustedKey("bad-key", []byte{0x01, 0x02, 0x03})

	req := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "ping",
		ID:        1,
		KeyID:     "bad-key",
		Signature: "00",
	}
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	err := v.VerifyRequest(req, addr)
	if err == nil {
		t.Error("should fail for invalid trusted key")
	}
	if !contains(err.Error(), "invalid trusted key") {
		t.Errorf("error should mention invalid trusted key: %s", err.Error())
	}
}

// --- SignRequest ---

func TestSignRequestEmptyKeyID(t *testing.T) {
	privKey := generateTestKey(t)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1}
	err := SignRequest(req, "", privKey)
	if err == nil {
		t.Error("should fail for empty keyID")
	}
}

func TestSignRequestNilPrivateKey(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1}
	err := SignRequest(req, "key-1", nil)
	if err == nil {
		t.Error("should fail for nil private key")
	}
}

func TestSignRequestWrongCurve(t *testing.T) {
	// Generate a P-384 key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1}
	err = SignRequest(req, "key-1", privKey)
	if err == nil {
		t.Error("should fail for non-P-256 key")
	}
}

func TestSignRequestSetsFields(t *testing.T) {
	privKey := generateTestKey(t)
	req := &JSONRPCRequest{JSONRPC: JSONRPCVersion, Method: "ping", ID: 1}
	if err := SignRequest(req, "my-key", privKey); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if req.KeyID != "my-key" {
		t.Errorf("KeyID = %s, want 'my-key'", req.KeyID)
	}
	if req.Signature == "" {
		t.Error("Signature should be set")
	}
	// Signature should be valid hex
	if _, err := hex.DecodeString(req.Signature); err != nil {
		t.Errorf("Signature is not valid hex: %v", err)
	}
}

// --- publicKeyFromSEC1 ---

func TestPublicKeyFromSEC1Valid(t *testing.T) {
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	pub, err := publicKeyFromSEC1(pubBytes)
	if err != nil {
		t.Fatalf("publicKeyFromSEC1: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", pub.Curve)
	}
}

func TestPublicKeyFromSEC1Invalid(t *testing.T) {
	_, err := publicKeyFromSEC1([]byte{0x00, 0x01})
	if err == nil {
		t.Error("should fail for invalid SEC 1 bytes")
	}
}

// --- canonicalRequestForSigning ---

func TestCanonicalRequestForSigning(t *testing.T) {
	req1 := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "ping",
		ID:        1,
		KeyID:     "key-1",
		Signature: "abc",
	}
	req2 := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "ping",
		ID:        1,
		KeyID:     "different-key",
		Signature: "different-sig",
	}

	c1, _ := canonicalRequestForSigning(req1)
	c2, _ := canonicalRequestForSigning(req2)

	// Both should produce the same canonical form (KeyID and Signature zeroed)
	if string(c1) != string(c2) {
		t.Errorf("canonical forms differ:\n  c1=%s\n  c2=%s", c1, c2)
	}
}

func TestCanonicalRequestForSigningPreservesParams(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC:   JSONRPCVersion,
		Method:    "tools/call",
		Params:    []byte(`{"name":"get_uptime","arguments":{"device":"pump01"}}`),
		ID:        42,
		KeyID:     "key-1",
		Signature: "somesig",
	}
	canon, err := canonicalRequestForSigning(req)
	if err != nil {
		t.Fatalf("canonicalRequestForSigning: %v", err)
	}
	if !contains(string(canon), "get_uptime") {
		t.Errorf("canonical form should preserve params: %s", canon)
	}
	if !contains(string(canon), "pump01") {
		t.Errorf("canonical form should preserve nested params: %s", canon)
	}
}

// --- helper ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestContainsHelper(t *testing.T) {
	if !contains("hello world", "world") {
		t.Error("contains should find 'world'")
	}
	if contains("hello", "world") {
		t.Error("contains should not find 'world' in 'hello'")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	v := NewSignatureVerifier()
	privKey := generateTestKey(t)
	pubBytes := publicKeyToSEC1(&privKey.PublicKey)
	v.AddTrustedKey("roundtrip-key", pubBytes)

	// Multiple requests
	for i := 1; i <= 5; i++ {
		req := &JSONRPCRequest{
			JSONRPC: JSONRPCVersion,
			Method:  "tools/call",
			Params:  []byte(fmt.Sprintf(`{"name":"tool_%d"}`, i)),
			ID:      i,
		}
		if err := SignRequest(req, "roundtrip-key", privKey); err != nil {
			t.Fatalf("SignRequest %d: %v", i, err)
		}
		addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		if err := v.VerifyRequest(req, addr); err != nil {
			t.Errorf("VerifyRequest %d: %v", i, err)
		}
	}
}
