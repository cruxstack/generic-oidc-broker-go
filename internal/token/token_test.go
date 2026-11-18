package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const issuer = "https://broker.example.com/providers/github"

var identity = Identity{
	Subject:           "github:42",
	Name:              "Ada",
	PreferredUsername: "ada",
	Email:             "ada@example.com",
	EmailVerified:     false,
	Picture:           "https://example.com/ada.png",
}

var testKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(Key{ID: "key-1", PEM: pkcs8PEM(t, testKey())})
	require.NoError(t, err)
	return s
}

func decode(t *testing.T, jwt string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3)
	for i, dst := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, dst))
	}
	return header, claims
}

func TestNewService_KeyFormats(t *testing.T) {
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey())})
	_, err := NewService(Key{ID: "k", PEM: pkcs1})
	assert.NoError(t, err, "PKCS #1")

	_, err = NewService(Key{ID: "k", PEM: pkcs8PEM(t, testKey())})
	assert.NoError(t, err, "PKCS #8")
}

func TestNewService_RejectsUnsuitableKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := map[string]struct {
		pem     []byte
		wantErr string
	}{
		"not PEM":     {[]byte("nope"), "not PEM"},
		"small RSA":   {pkcs8PEM(t, small), "1024 bits"},
		"not RSA":     {pkcs8PEM(t, ec), "not RSA"},
		"corrupt DER": {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), "parsing"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewService(Key{ID: "k", PEM: tt.pem})
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestJWKS_PublishesOnlyThePublicKey(t *testing.T) {
	raw, err := json.Marshal(newService(t).JWKS())
	require.NoError(t, err)

	var set struct{ Keys []map[string]any }
	require.NoError(t, json.Unmarshal(raw, &set))
	require.Len(t, set.Keys, 1)
	assert.Equal(t, "key-1", set.Keys[0]["kid"])
	assert.Equal(t, "RS256", set.Keys[0]["alg"])
	assert.NotContains(t, set.Keys[0], "d")
}

func TestSignIDToken(t *testing.T) {
	s := newService(t)
	raw, err := s.SignIDToken(IDToken{Issuer: issuer, ClientID: "app", Identity: identity, Nonce: "n-1", Code: "the-code"})
	require.NoError(t, err)

	header, claims := decode(t, raw)
	assert.Equal(t, "JWT", header["typ"])
	assert.Equal(t, "key-1", header["kid"])
	assert.Equal(t, "RS256", header["alg"])
	assert.Equal(t, issuer, claims["iss"])
	assert.Equal(t, []any{"app"}, claims["aud"])
	assert.Equal(t, "github:42", claims["sub"])
	assert.Equal(t, "n-1", claims["nonce"])
	assert.Equal(t, false, claims["email_verified"], "email_verified accompanies the email even when false")
	assert.Equal(t, leftHalfHash("the-code"), claims["c_hash"])
	assert.NotEmpty(t, claims["jti"])
}

func TestAccessTokenRoundTrip(t *testing.T) {
	s := newService(t)
	raw, err := s.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Scope: "openid email", Identity: identity})
	require.NoError(t, err)

	header, _ := decode(t, raw)
	assert.Equal(t, "at+jwt", header["typ"])

	got, err := s.VerifyAccessToken(raw, issuer)
	require.NoError(t, err)
	assert.Equal(t, &AccessToken{Issuer: issuer, ClientID: "app", Scope: "openid email", Identity: identity}, got)
}

func TestVerifyAccessToken_Rejects(t *testing.T) {
	s := newService(t)
	accessToken, err := s.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Scope: "openid", Identity: identity})
	require.NoError(t, err)
	idToken, err := s.SignIDToken(IDToken{Issuer: issuer, ClientID: "app", Identity: identity})
	require.NoError(t, err)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := NewService(Key{ID: "key-1", PEM: pkcs8PEM(t, otherKey)})
	require.NoError(t, err)
	forged, err := other.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Identity: identity})
	require.NoError(t, err)

	tests := map[string]struct{ raw, issuer string }{
		"ID token":     {idToken, issuer},
		"other issuer": {accessToken, "https://broker.example.com/providers/google"},
		"other key":    {forged, issuer},
		"malformed":    {"a.b.c", issuer},
		"empty":        {"", issuer},
		"truncated":    {accessToken[:len(accessToken)-10], issuer},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.VerifyAccessToken(tt.raw, tt.issuer)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestVerifyAccessToken_RejectsExpired(t *testing.T) {
	s := newService(t)
	raw, err := s.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Identity: identity})
	require.NoError(t, err)

	s.now = func() time.Time { return time.Now().Add(AccessTokenTTL + time.Minute) }
	_, err = s.VerifyAccessToken(raw, issuer)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestIdentityClaims(t *testing.T) {
	assert.Equal(t, map[string]any{"sub": "x"}, Identity{Subject: "x"}.Claims())
	assert.Equal(t, map[string]any{
		"sub": "x", "email": "e@example.com", "email_verified": true,
	}, Identity{Subject: "x", Email: "e@example.com", EmailVerified: true}.Claims())
}

func TestKeyRotation(t *testing.T) {
	old := newService(t)
	issued, err := old.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Identity: identity})
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&testKey().PublicKey)
	require.NoError(t, err)
	oldPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rotated, err := NewService(Key{ID: "key-2", PEM: pkcs8PEM(t, newKey)}, Key{ID: "key-1", PEM: oldPublicPEM})
	require.NoError(t, err)

	_, err = rotated.VerifyAccessToken(issued, issuer)
	assert.NoError(t, err, "tokens signed with the previous key stay valid")

	fresh, err := rotated.SignAccessToken(AccessToken{Issuer: issuer, ClientID: "app", Identity: identity})
	require.NoError(t, err)
	header, _ := decode(t, fresh)
	assert.Equal(t, "key-2", header["kid"], "new tokens use the new key")

	raw, err := json.Marshal(rotated.JWKS())
	require.NoError(t, err)
	var set struct{ Keys []struct{ Kid string } }
	require.NoError(t, json.Unmarshal(raw, &set))
	assert.ElementsMatch(t, []string{"key-1", "key-2"}, []string{set.Keys[0].Kid, set.Keys[1].Kid})
}
