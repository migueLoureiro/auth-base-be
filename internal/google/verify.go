// Package google verifies Google Sign-In ID tokens using Google's public JWKS endpoint.
// Uses only the Go standard library — no external dependencies.
package google

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// User holds the verified claims extracted from a Google ID token.
type User struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

// VerifyIDToken validates a Google ID token JWT and returns the user claims.
func VerifyIDToken(idToken, clientID string) (*User, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT: expected 3 parts")
	}

	// Decode header to get kid and alg.
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Decode and parse payload.
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Sub     string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
		Aud     any    `json:"aud"` // string or []string
		Iss     string `json:"iss"`
		Exp     int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}

	// Validate issuer.
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
	}

	// Validate expiry.
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}

	// Validate audience.
	if !audienceMatches(claims.Aud, clientID) {
		return nil, errors.New("token audience mismatch")
	}

	// Fetch matching Google public key.
	pubKey, err := getPublicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("fetch public key: %w", err)
	}

	// Verify RS256 signature over "header.payload".
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("signature verification failed")
	}

	if claims.Sub == "" {
		return nil, errors.New("missing subject (sub) claim")
	}

	return &User{
		UUID:    claims.Sub,
		Name:    claims.Name,
		Email:   claims.Email,
		Picture: claims.Picture,
	}, nil
}

// audienceMatches handles "aud" as either a string or array.
func audienceMatches(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// ---- JWKS cache (in-memory, refreshed every hour) ----

const googleCertsURL = "https://www.googleapis.com/oauth2/v1/certs"

var (
	certsMu      sync.RWMutex
	certsCache   map[string]*rsa.PublicKey
	certsCachedAt time.Time
	certsTTL     = 1 * time.Hour
)

func getPublicKey(kid string) (*rsa.PublicKey, error) {
	certsMu.RLock()
	if time.Since(certsCachedAt) < certsTTL {
		if key, ok := certsCache[kid]; ok {
			certsMu.RUnlock()
			return key, nil
		}
	}
	certsMu.RUnlock()

	keys, err := fetchCerts()
	if err != nil {
		return nil, fmt.Errorf("fetch Google certs: %w", err)
	}

	certsMu.Lock()
	certsCache = keys
	certsCachedAt = time.Now()
	certsMu.Unlock()

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("key id %q not found", kid)
	}
	return key, nil
}

// fetchCerts fetches Google's public certificates (PEM format from v1 endpoint).
func fetchCerts() (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(googleCertsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Response is a JSON object: { "kid": "<PEM cert>", ... }
	var rawCerts map[string]string
	if err := json.Unmarshal(body, &rawCerts); err != nil {
		return nil, fmt.Errorf("parse certs JSON: %w", err)
	}

	result := make(map[string]*rsa.PublicKey, len(rawCerts))
	for kid, pemStr := range rawCerts {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		result[kid] = rsaKey
	}
	return result, nil
}

// base64URLDecode decodes a base64url-encoded string (with or without padding).
// base64URLDecode decodes a base64url-encoded string (no padding required).
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}


