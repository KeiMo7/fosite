// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func newRequester(t *testing.T, id string) fosite.Requester {
	t.Helper()
	req := fosite.NewRequest()
	req.SetID(id)
	return req
}

func TestRotateRefreshTokenIsSingleUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore()

	req := newRequester(t, "family")
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))

	const goroutines = 64
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		serial  int
		other   []error
	)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			err := store.RotateRefreshToken(ctx, "family", "refresh-1")

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case assert.ErrorIs(t, err, fosite.ErrSerializationFailure):
				serial++
			default:
				other = append(other, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Empty(t, other)
	assert.Equal(t, 1, success)
	assert.Equal(t, goroutines-1, serial)

	_, err := store.GetAccessTokenSession(ctx, "access-1", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)

	_, err = store.GetRefreshTokenSession(ctx, "refresh-1", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

func TestRotateRefreshTokenValidation(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name      string
		requestID string
		signature string
		prepare   func(t *testing.T, store *MemoryStore)
		expected  error
	}{
		{
			name:      "empty signature",
			requestID: "family",
			signature: "",
			prepare:   func(t *testing.T, store *MemoryStore) {},
			expected:  fosite.ErrNotFound,
		},
		{
			name:      "unknown signature",
			requestID: "family",
			signature: "unknown",
			prepare:   func(t *testing.T, store *MemoryStore) {},
			expected:  fosite.ErrNotFound,
		},
		{
			name:      "request id mismatch",
			requestID: "other",
			signature: "refresh-1",
			prepare: func(t *testing.T, store *MemoryStore) {
				req := newRequester(t, "family")
				require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
				require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
			},
			expected: fosite.ErrNotFound,
		},
		{
			name:      "inactive signature",
			requestID: "family",
			signature: "refresh-1",
			prepare: func(t *testing.T, store *MemoryStore) {
				req := newRequester(t, "family")
				require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
				require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
				require.NoError(t, store.RevokeRefreshToken(ctx, "family"))
			},
			expected: fosite.ErrSerializationFailure,
		},
		{
			name:      "stale signature",
			requestID: "family",
			signature: "refresh-1",
			prepare: func(t *testing.T, store *MemoryStore) {
				req := newRequester(t, "family")
				require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
				require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
				require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
				require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))
			},
			expected: fosite.ErrSerializationFailure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryStore()
			tc.prepare(t, store)

			err := store.RotateRefreshToken(ctx, tc.requestID, tc.signature)
			require.ErrorIs(t, err, tc.expected)

			// A failed rotation must not delete any tokens.
			for _, signature := range []string{"access-1", "access-2"} {
				if _, ok := store.AccessTokens[signature]; ok {
					_, err := store.GetAccessTokenSession(ctx, signature, nil)
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestRotateRefreshTokenOnlyRevokesPresentedToken(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	req := newRequester(t, "family")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
	require.NoError(t, store.RotateRefreshToken(ctx, "family", "refresh-1"))

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))

	// The access token of the next generation is still valid: only the
	// presented refresh token and its paired access token were consumed.
	_, err := store.GetAccessTokenSession(ctx, "access-2", nil)
	require.NoError(t, err)

	require.NoError(t, store.RotateRefreshToken(ctx, "family", "refresh-2"))
	_, err = store.GetAccessTokenSession(ctx, "access-2", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestRevokeAccessTokenFamily(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	req := newRequester(t, "family")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))

	require.NoError(t, store.RevokeAccessToken(ctx, "family"))

	for _, signature := range []string{"access-1", "access-2"} {
		_, err := store.GetAccessTokenSession(ctx, signature, nil)
		require.ErrorIs(t, err, fosite.ErrNotFound)
	}

	// Refresh tokens are untouched by access token revocation.
	_, err := store.GetRefreshTokenSession(ctx, "refresh-2", nil)
	require.NoError(t, err)

	// Unknown request IDs are idempotent.
	require.NoError(t, store.RevokeAccessToken(ctx, "unknown"))
}

func TestRevokeRefreshTokenFamily(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	req := newRequester(t, "family")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))

	require.NoError(t, store.RevokeRefreshToken(ctx, "family"))

	for _, signature := range []string{"refresh-1", "refresh-2"} {
		_, err := store.GetRefreshTokenSession(ctx, signature, nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
	}

	// Access tokens are untouched by refresh token revocation.
	_, err := store.GetAccessTokenSession(ctx, "access-2", nil)
	require.NoError(t, err)

	// Unknown request IDs are idempotent.
	require.NoError(t, store.RevokeRefreshToken(ctx, "unknown"))
}

func TestDeleteTokenSessionRemovesFamilyEntries(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	req := newRequester(t, "family")

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))

	require.NoError(t, store.DeleteAccessTokenSession(ctx, "access-1"))
	require.NoError(t, store.DeleteRefreshTokenSession(ctx, "refresh-1"))

	assert.Empty(t, store.accessTokenFamilies["family"])
	assert.Empty(t, store.refreshTokenFamilies["family"])
	require.NotContains(t, store.accessTokenFamilies, "family")
	require.NotContains(t, store.refreshTokenFamilies, "family")

	// Deleting unknown signatures is idempotent.
	require.NoError(t, store.DeleteAccessTokenSession(ctx, "unknown"))
	require.NoError(t, store.DeleteRefreshTokenSession(ctx, "unknown"))
}

func TestMemoryStoreLiteralConstruction(t *testing.T) {
	ctx := context.Background()

	newStore := func() *MemoryStore {
		return &MemoryStore{
			AccessTokens:           map[string]fosite.Requester{},
			RefreshTokens:          map[string]StoreRefreshToken{},
			AccessTokenRequestIDs:  map[string]string{},
			RefreshTokenRequestIDs: map[string]string{},
		}
	}

	for _, store := range []*MemoryStore{newStore(), NewMemoryStore()} {
		req := newRequester(t, "family")

		require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))

		_, err := store.GetRefreshTokenSession(ctx, "refresh-1", nil)
		require.NoError(t, err)

		// Rotation works on a literal store exactly as on a constructed one.
		require.NoError(t, store.RotateRefreshToken(ctx, "family", "refresh-1"))
		_, err = store.GetRefreshTokenSession(ctx, "refresh-1", nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
		_, err = store.GetAccessTokenSession(ctx, "access-1", nil)
		require.ErrorIs(t, err, fosite.ErrNotFound)

		require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))
		require.NoError(t, store.RevokeAccessToken(ctx, "family"))
		_, err = store.GetAccessTokenSession(ctx, "access-2", nil)
		require.ErrorIs(t, err, fosite.ErrNotFound)
		require.NoError(t, store.RevokeRefreshToken(ctx, "family"))
		_, err = store.GetRefreshTokenSession(ctx, "refresh-2", nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
	}

	// The zero value must not panic either.
	zero := &MemoryStore{}
	req := newRequester(t, "family")
	require.NoError(t, zero.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, zero.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
	require.NoError(t, zero.RevokeAccessToken(ctx, "family"))
	require.NoError(t, zero.RevokeRefreshToken(ctx, "family"))
	require.NoError(t, zero.DeleteAccessTokenSession(ctx, "unknown"))
	require.NoError(t, zero.DeleteRefreshTokenSession(ctx, "unknown"))
	require.ErrorIs(t, zero.RotateRefreshToken(ctx, "family", "refresh-1"), fosite.ErrSerializationFailure)
}

func TestRefreshTokenRequestIDsPointsAtLatest(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	req := newRequester(t, "family")

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-1", "access-1", req))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-2", "access-2", req))
	assert.Equal(t, "refresh-2", store.RefreshTokenRequestIDs["family"])

	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-1", req))
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-2", req))
	assert.Equal(t, "access-2", store.AccessTokenRequestIDs["family"])
}
