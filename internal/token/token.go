// Package token signs and verifies the JWTs the broker issues: ID tokens
// (OIDC Core) and access tokens (RFC 9068 JWT profile).
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Token lifetimes.
const (
	IDTokenTTL     = time.Hour
	AccessTokenTTL = time.Hour
)

const (
	// accessTokenType is the JWT "typ" header that marks access tokens
	// (RFC 9068 §2.1), so that an ID token can never be used as one.
	accessTokenType = "at+jwt"
	idTokenType     = "JWT"
	minRSAKeyBits   = 2048
)

// ErrInvalidToken is returned for tokens that fail verification.
var ErrInvalidToken = errors.New("invalid token")

// Key is a PEM-encoded RSA key and its key ID ("kid").
type Key struct {
	ID  string
	PEM []byte
}

// Service signs tokens with the broker's RSA key and verifies them.
type Service struct {
	signingKey jwk.Key
	// jwks holds the public keys tokens are verified with: the signing key
	// and any previous keys still trusted during a rotation.
	jwks jwk.Set
	now  func() time.Time
}

// NewService creates a Service that signs with signing, an RSA private key
// (PKCS #8 or PKCS #1) of at least 2048 bits. Tokens signed with previous
// keys, which may be public or private, are still accepted, and the keys are
// still published, so that the signing key can be rotated without
// invalidating tokens already issued.
func NewService(signing Key, previous ...Key) (*Service, error) {
	privateKey, err := parseRSAPrivateKey(signing.PEM)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	signingKey, err := jwk.Import[jwk.Key](privateKey)
	if err != nil {
		return nil, fmt.Errorf("importing signing key: %w", err)
	}
	if err := setKeyAttributes(signingKey, signing.ID); err != nil {
		return nil, err
	}

	jwks := jwk.NewSet()
	if err := addPublicKey(jwks, &privateKey.PublicKey, signing.ID); err != nil {
		return nil, err
	}
	for _, key := range previous {
		publicKey, err := parseRSAPublicKey(key.PEM)
		if err != nil {
			return nil, fmt.Errorf("previous key %q: %w", key.ID, err)
		}
		if err := addPublicKey(jwks, publicKey, key.ID); err != nil {
			return nil, err
		}
	}

	return &Service{signingKey: signingKey, jwks: jwks, now: time.Now}, nil
}

func addPublicKey(set jwk.Set, publicKey *rsa.PublicKey, keyID string) error {
	key, err := jwk.Import[jwk.Key](publicKey)
	if err != nil {
		return fmt.Errorf("importing public key %q: %w", keyID, err)
	}
	if err := setKeyAttributes(key, keyID); err != nil {
		return err
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("setting key usage: %w", err)
	}
	return set.AddKey(key)
}

func setKeyAttributes(key jwk.Key, keyID string) error {
	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("setting key ID: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return fmt.Errorf("setting key algorithm: %w", err)
	}
	return nil
}

func parseRSAPrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("key is not PEM encoded")
	}

	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, not RSA", parsed)
		}
		key = rsaKey
	} else if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return key, checkKeySize(&key.PublicKey)
}

// parseRSAPublicKey reads an RSA public key from a PEM-encoded public key
// (PKIX or PKCS #1) or private key.
func parseRSAPublicKey(keyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("key is not PEM encoded")
	}

	var key *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, not RSA", parsed)
		}
		key = rsaKey
	case "RSA PUBLIC KEY":
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		key = rsaKey
	default:
		privateKey, err := parseRSAPrivateKey(keyPEM)
		if err != nil {
			return nil, err
		}
		key = &privateKey.PublicKey
	}
	return key, checkKeySize(key)
}

func checkKeySize(key *rsa.PublicKey) error {
	if bits := key.N.BitLen(); bits < minRSAKeyBits {
		return fmt.Errorf("key is %d bits; at least %d are required", bits, minRSAKeyBits)
	}
	return nil
}

// JWKS returns the public key set clients use to verify tokens.
func (s *Service) JWKS() jwk.Set {
	return s.jwks
}

// IDToken describes an ID token to sign.
type IDToken struct {
	Issuer   string
	ClientID string
	Identity Identity
	Nonce    string
	// Code, when set, is the authorization code returned alongside the ID
	// token in a hybrid flow; its hash is included as c_hash.
	Code string
}

// SignIDToken returns a signed ID token.
func (s *Service) SignIDToken(t IDToken) (string, error) {
	claims := t.Identity.Claims()
	if t.Nonce != "" {
		claims["nonce"] = t.Nonce
	}
	if t.Code != "" {
		claims["c_hash"] = leftHalfHash(t.Code)
	}
	return s.sign(idTokenType, t.Issuer, t.ClientID, IDTokenTTL, claims)
}

// AccessToken describes an access token, either to sign or as verified.
type AccessToken struct {
	Issuer   string
	ClientID string
	Scope    string
	Identity Identity
}

// SignAccessToken returns a signed access token. The identity's profile
// claims are embedded so the userinfo endpoint can serve them statelessly.
func (s *Service) SignAccessToken(t AccessToken) (string, error) {
	claims := t.Identity.Claims()
	claims["client_id"] = t.ClientID
	claims["scope"] = t.Scope
	return s.sign(accessTokenType, t.Issuer, t.ClientID, AccessTokenTTL, claims)
}

// VerifyAccessToken checks that raw is an unexpired access token signed by
// this service for issuer. ID tokens are rejected.
func (s *Service) VerifyAccessToken(raw, issuer string) (*AccessToken, error) {
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("%w: malformed JWT", ErrInvalidToken)
	}
	if typ, _ := msg.Signatures()[0].ProtectedHeaders().Type(); !strings.EqualFold(typ, accessTokenType) {
		return nil, fmt.Errorf("%w: not an access token", ErrInvalidToken)
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(s.jwks),
		jwt.WithIssuer(issuer),
		jwt.WithClock(jwt.ClockFunc(s.now)),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	identity, err := identityFromToken(tok)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	clientID, _ := jwt.Get[string](tok, "client_id")
	scope, _ := jwt.Get[string](tok, "scope")
	return &AccessToken{Issuer: issuer, ClientID: clientID, Scope: scope, Identity: identity}, nil
}

func (s *Service) sign(typ, issuer, audience string, ttl time.Duration, claims map[string]any) (string, error) {
	now := s.now()
	builder := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(rand.Text())
	for name, value := range claims {
		builder = builder.Claim(name, value)
	}
	tok, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, typ); err != nil {
		return "", fmt.Errorf("setting token type: %w", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), s.signingKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return string(signed), nil
}

// leftHalfHash computes the c_hash/at_hash value of OIDC Core §3.3.2.11: the
// base64url-encoded left half of the SHA-256 hash of value.
func leftHalfHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
