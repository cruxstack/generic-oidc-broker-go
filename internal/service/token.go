package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// Token expiration durations.
const (
	// IDTokenExpiry is the lifetime of an ID token.
	IDTokenExpiry = 1 * time.Hour

	// AccessTokenExpiry is the lifetime of an access token.
	AccessTokenExpiry = 1 * time.Hour
)

// TokenService handles JWT token creation and validation.
type TokenService struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
	signingKey jwk.Key
	jwkSet     jwk.Set
	logger     *slog.Logger
}

// NewTokenService creates a new token service.
func NewTokenService(cfg *config.Config, logger *slog.Logger) (*TokenService, error) {
	var pemData []byte
	var err error

	// Load private key from PEM data or file
	if len(cfg.KeyPrivatePEM) > 0 {
		pemData = cfg.KeyPrivatePEM
	} else if cfg.KeyPrivatePEMPath != "" {
		pemData, err = os.ReadFile(cfg.KeyPrivatePEMPath)
		if err != nil {
			return nil, fmt.Errorf("reading private key file: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no private key configured")
	}

	// Parse PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse private key
	var privateKey *rsa.PrivateKey

	// Try PKCS#8 first, then PKCS#1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#1
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
	} else {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	// Create JWK from public key for JWKS endpoint
	pubJWK, err := jwk.FromRaw(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating JWK from public key: %w", err)
	}

	// Set JWK properties
	if err := pubJWK.Set(jwk.KeyIDKey, cfg.KeyID); err != nil {
		return nil, fmt.Errorf("setting key ID: %w", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("setting algorithm: %w", err)
	}
	if err := pubJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("setting key usage: %w", err)
	}

	// Create JWK set
	jwkSet := jwk.NewSet()
	if err := jwkSet.AddKey(pubJWK); err != nil {
		return nil, fmt.Errorf("adding key to set: %w", err)
	}

	// Create signing key from private key with kid set
	signingKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating signing key: %w", err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, cfg.KeyID); err != nil {
		return nil, fmt.Errorf("setting signing key ID: %w", err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, fmt.Errorf("setting signing algorithm: %w", err)
	}

	return &TokenService{
		cfg:        cfg,
		privateKey: privateKey,
		signingKey: signingKey,
		jwkSet:     jwkSet,
		logger:     logger,
	}, nil
}

// IDTokenClaims represents the claims for an ID token.
type IDTokenClaims struct {
	Subject         string // Format: "provider:id" (e.g., "twitter:12345")
	Name            string
	PreferredUser   string // Username/handle
	Email           string
	EmailVerified   bool
	ProfileImageURL string
	ClientID        string
	Nonce           string
	Issuer          string // Optional: override the issuer (for provider-scoped tokens)
}

// AccessTokenClaims represents the claims for an access token.
type AccessTokenClaims struct {
	Subject  string // Format: "provider:id" (e.g., "twitter:12345")
	ClientID string
	Scope    string
	Issuer   string // Optional: override the issuer (for provider-scoped tokens)
}

// CreateIDToken creates a signed ID token.
func (s *TokenService) CreateIDToken(claims *IDTokenClaims) (string, error) {
	now := time.Now()

	// Use custom issuer if provided, otherwise default to config issuer
	issuer := s.cfg.OIDCIssuer
	if claims.Issuer != "" {
		issuer = claims.Issuer
	}

	builder := jwt.NewBuilder().
		Issuer(issuer).
		Subject(claims.Subject).
		Audience([]string{claims.ClientID}).
		IssuedAt(now).
		Expiration(now.Add(IDTokenExpiry))

	// Add optional claims if present
	if claims.Name != "" {
		builder = builder.Claim("name", claims.Name)
	}
	if claims.PreferredUser != "" {
		builder = builder.Claim("preferred_username", claims.PreferredUser)
	}
	if claims.ProfileImageURL != "" {
		builder = builder.Claim("picture", claims.ProfileImageURL)
	}
	if claims.Email != "" {
		builder = builder.Claim("email", claims.Email)
		builder = builder.Claim("email_verified", claims.EmailVerified)
	}
	if claims.Nonce != "" {
		builder = builder.Claim("nonce", claims.Nonce)
	}

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	// Sign the token using the signing key (which has kid set)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, s.signingKey))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return string(signed), nil
}

// CreateAccessToken creates a signed access token.
func (s *TokenService) CreateAccessToken(claims *AccessTokenClaims) (string, error) {
	now := time.Now()

	scope := claims.Scope
	if scope == "" {
		scope = "openid"
	}

	// Use custom issuer if provided, otherwise default to config issuer
	issuer := s.cfg.OIDCIssuer
	if claims.Issuer != "" {
		issuer = claims.Issuer
	}

	token, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(claims.Subject).
		Audience([]string{claims.ClientID}).
		IssuedAt(now).
		Expiration(now.Add(AccessTokenExpiry)).
		Claim("scope", scope).
		Build()
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	// Sign the token using the signing key (which has kid set)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, s.signingKey))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return string(signed), nil
}

// GetJWKS returns the JSON Web Key Set for token verification.
func (s *TokenService) GetJWKS() jwk.Set {
	return s.jwkSet
}

// ParseAccessToken parses and validates an access token.
// It accepts tokens with the default issuer or any provider-scoped issuer.
func (s *TokenService) ParseAccessToken(tokenString string) (jwt.Token, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.RS256, &s.privateKey.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	// Validate issuer - accept default issuer or any provider-scoped issuer
	tokenIssuer := token.Issuer()
	if tokenIssuer != s.cfg.OIDCIssuer && !s.isProviderIssuer(tokenIssuer) {
		return nil, fmt.Errorf("invalid issuer")
	}

	return token, nil
}

// isProviderIssuer checks if the given issuer is a valid provider-scoped issuer.
func (s *TokenService) isProviderIssuer(issuer string) bool {
	// Provider-scoped issuers have the format: {OIDCIssuer}/providers/{providerName}
	prefix := s.cfg.OIDCIssuer + "/providers/"
	return len(issuer) > len(prefix) && issuer[:len(prefix)] == prefix
}
