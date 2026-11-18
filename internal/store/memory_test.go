package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

var code = AuthCode{ClientID: "app", RedirectURI: "https://app/cb", Identity: token.Identity{Subject: "github:1"}}

func TestMemory_ConsumeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	require.NoError(t, m.Save(ctx, "abc", code))

	got, err := m.Consume(ctx, "abc")
	require.NoError(t, err)
	assert.Equal(t, code, got)

	_, err = m.Consume(ctx, "abc")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemory_UnknownCode(t *testing.T) {
	_, err := NewMemory().Consume(context.Background(), "nope")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestMemory_Expiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	m := NewMemory()
	m.now = func() time.Time { return now }

	require.NoError(t, m.Save(ctx, "old", code))
	require.NoError(t, m.Save(ctx, "redeemable", code))

	now = now.Add(AuthCodeTTL + time.Second)
	_, err := m.Consume(ctx, "old")
	assert.ErrorIs(t, err, ErrNotFound, "expired codes can't be redeemed")

	now = now.Add(sweepInterval)
	require.NoError(t, m.Save(ctx, "new", code))
	assert.NotContains(t, m.codes, "redeemable", "saving sweeps expired codes")
	assert.Contains(t, m.codes, "new")
}
