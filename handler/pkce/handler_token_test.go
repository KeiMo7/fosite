// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

// pkceTestHandler builds a handler backed by a fresh memory store.
func pkceTestHandler(t *testing.T, config *fosite.Config, code string) (*Handler, *mockCodeStrategy) {
	t.Helper()
	strategy := &mockCodeStrategy{signature: code}
	return &Handler{
		Storage:               newPKCEStore(t),
		AuthorizeCodeStrategy: strategy,
		Config:                config,
	}, strategy
}

func newPKCEStore(t *testing.T) *pkceRequestStore {
	t.Helper()
	return &pkceRequestStore{sessions: map[string]fosite.Requester{}}
}

// pkceRequestStore is an in-memory PKCERequestStorage implementation that
// allows tests to inject errors.
type pkceRequestStore struct {
	sessions     map[string]fosite.Requester
	getErr       error
	deleteErr    error
	deleteCalled bool
}

func (s *pkceRequestStore) GetPKCERequestSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	req, ok := s.sessions[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *pkceRequestStore) CreatePKCERequestSession(_ context.Context, signature string, requester fosite.Requester) error {
	s.sessions[signature] = requester
	return nil
}

func (s *pkceRequestStore) DeletePKCERequestSession(_ context.Context, signature string) error {
	s.deleteCalled = true
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.sessions, signature)
	return nil
}

func storeAuthorizeRequest(t *testing.T, store *pkceRequestStore, signature, challenge, method string) {
	t.Helper()
	ar := fosite.NewAuthorizeRequest()
	ar.Client = &fosite.DefaultClient{Public: true}
	if challenge != "" {
		ar.Form.Add("code_challenge", challenge)
	}
	if method != "" {
		ar.Form.Add("code_challenge_method", method)
	}
	require.NoError(t, store.CreatePKCERequestSession(context.Background(), signature, ar))
}

func newCodeRequest(verifier string) *fosite.AccessRequest {
	r := fosite.NewAccessRequest(nil)
	r.Client = &fosite.DefaultClient{Public: true}
	r.GrantTypes = fosite.Arguments{"authorization_code"}
	if verifier != "" {
		r.Form.Add("code_verifier", verifier)
	}
	return r
}

func TestHandleTokenEndpointRequestPKCECanBeRetried(t *testing.T) {
	config := &fosite.Config{EnforcePKCE: true}
	handler, _ := pkceTestHandler(t, config, "code")
	store := handler.Storage.(*pkceRequestStore)

	verifier := validVerifier(64)
	challenge, err := S256Challenge(verifier)
	require.NoError(t, err)
	storeAuthorizeRequest(t, store, "code", challenge, "S256")

	// A wrong verifier fails without consuming the session.
	err = handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(validVerifier(65)))
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)

	req, err := store.GetPKCERequestSession(context.Background(), "code", nil)
	require.NoError(t, err)
	require.NotNil(t, req)

	// The same code with the correct verifier succeeds.
	require.NoError(t, handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier)))

	// The session has been consumed.
	_, err = store.GetPKCERequestSession(context.Background(), "code", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)

	// A second exchange of the same code fails.
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier)), fosite.ErrInvalidGrant)
}

func TestHandleTokenEndpointRequestVerifierErrorOrder(t *testing.T) {
	verifier := validVerifier(64)
	challenge, err := S256Challenge(verifier)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		verifier  string
		challenge string
		method    string
		hint      string
	}{
		{
			name:      "verifier too short wins over malformed challenge",
			verifier:  "short",
			challenge: "malformed",
			method:    "S256",
			hint:      "The PKCE code verifier must be at least 43 characters.",
		},
		{
			name:      "verifier too long wins over malformed challenge",
			verifier:  validVerifier(129),
			challenge: "malformed",
			method:    "S256",
			hint:      "The PKCE code verifier can not be longer than 128 characters.",
		},
		{
			name:      "malformed verifier wins over malformed challenge",
			verifier:  validVerifier(42) + "!",
			challenge: "malformed",
			method:    "S256",
			hint:      "The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'.",
		},
		{
			name:      "malformed challenge reported as mismatch",
			verifier:  verifier,
			challenge: "malformed",
			method:    "S256",
			hint:      "The PKCE code challenge did not match the code verifier.",
		},
		{
			name:      "wrong verifier reported as mismatch",
			verifier:  validVerifier(65),
			challenge: challenge,
			method:    "S256",
			hint:      "The PKCE code challenge did not match the code verifier.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &fosite.Config{EnforcePKCE: true, EnablePKCEPlainChallengeMethod: true}
			handler, _ := pkceTestHandler(t, config, "code")
			store := handler.Storage.(*pkceRequestStore)
			storeAuthorizeRequest(t, store, "code", tc.challenge, tc.method)

			err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(tc.verifier))
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)

			var rfcErr *fosite.RFC6749Error
			require.True(t, errors.As(err, &rfcErr))
			assert.Equal(t, tc.hint, rfcErr.HintField)
			assert.NotContains(t, err.Error(), tc.verifier)
			if tc.challenge != "" {
				assert.NotContains(t, rfcErr.HintField, tc.challenge)
				assert.NotContains(t, rfcErr.DebugField, tc.challenge)
			}
		})
	}
}

func TestHandleTokenEndpointRequestStorageErrors(t *testing.T) {
	verifier := validVerifier(64)
	challenge, err := S256Challenge(verifier)
	require.NoError(t, err)

	t.Run("get error", func(t *testing.T) {
		config := &fosite.Config{EnforcePKCE: true}
		handler, _ := pkceTestHandler(t, config, "code")
		store := handler.Storage.(*pkceRequestStore)
		store.getErr = errors.New("boom")

		err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier))
		require.ErrorIs(t, err, fosite.ErrServerError)
		assert.False(t, store.deleteCalled)
	})

	t.Run("delete error", func(t *testing.T) {
		config := &fosite.Config{EnforcePKCE: true}
		handler, _ := pkceTestHandler(t, config, "code")
		store := handler.Storage.(*pkceRequestStore)
		storeAuthorizeRequest(t, store, "code", challenge, "S256")
		store.deleteErr = errors.New("boom")

		err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier))
		require.ErrorIs(t, err, fosite.ErrServerError)
	})

	t.Run("missing session without verifier", func(t *testing.T) {
		config := &fosite.Config{}
		handler, _ := pkceTestHandler(t, config, "code")

		require.NoError(t, handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest("")))
	})

	t.Run("missing session without verifier but enforced", func(t *testing.T) {
		config := &fosite.Config{EnforcePKCE: true}
		handler, _ := pkceTestHandler(t, config, "code")

		err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(""))
		require.ErrorIs(t, err, fosite.ErrInvalidRequest)
	})

	t.Run("missing session with verifier", func(t *testing.T) {
		config := &fosite.Config{}
		handler, _ := pkceTestHandler(t, config, "code")

		err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier))
		require.ErrorIs(t, err, fosite.ErrInvalidGrant)

		var rfcErr *fosite.RFC6749Error
		require.True(t, errors.As(err, &rfcErr))
		assert.Equal(t, "Unable to find initial PKCE data tied to this request", rfcErr.HintField)
	})
}

func TestHandleTokenEndpointRequestPlainAndMissingChallenge(t *testing.T) {
	verifier := validVerifier(64)

	t.Run("plain succeeds without enforcement", func(t *testing.T) {
		config := &fosite.Config{EnablePKCEPlainChallengeMethod: true}
		handler, _ := pkceTestHandler(t, config, "code")
		store := handler.Storage.(*pkceRequestStore)
		storeAuthorizeRequest(t, store, "code", verifier, "")

		require.NoError(t, handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier)))
	})

	t.Run("plain is rejected when disabled", func(t *testing.T) {
		config := &fosite.Config{}
		handler, _ := pkceTestHandler(t, config, "code")
		store := handler.Storage.(*pkceRequestStore)
		storeAuthorizeRequest(t, store, "code", verifier, "")

		err := handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(verifier))
		require.ErrorIs(t, err, fosite.ErrInvalidRequest)

		var rfcErr *fosite.RFC6749Error
		require.True(t, errors.As(err, &rfcErr))
		assert.Equal(t, "Clients must use code_challenge_method=S256, plain is not allowed.", rfcErr.HintField)
	})

	t.Run("no pkce without enforcement deletes nothing it does not need", func(t *testing.T) {
		config := &fosite.Config{}
		handler, _ := pkceTestHandler(t, config, "code")
		store := handler.Storage.(*pkceRequestStore)
		storeAuthorizeRequest(t, store, "code", "", "")

		require.NoError(t, handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest("")))
		require.True(t, store.deleteCalled)
	})
}

func TestHandleTokenEndpointRequestDoesNotLeakSecrets(t *testing.T) {
	config := &fosite.Config{EnforcePKCE: true}
	handler, _ := pkceTestHandler(t, config, "code")
	store := handler.Storage.(*pkceRequestStore)
	verifier := validVerifier(64)
	challenge, err := S256Challenge(verifier)
	require.NoError(t, err)
	storeAuthorizeRequest(t, store, "code", challenge, "S256")

	err = handler.HandleTokenEndpointRequest(context.Background(), newCodeRequest(validVerifier(65)))
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.NotContains(t, fmt.Sprintf("%+v", err), challenge)
	assert.NotContains(t, rfcErr.DebugField, challenge)
	assert.NotContains(t, rfcErr.HintField, challenge)
}
