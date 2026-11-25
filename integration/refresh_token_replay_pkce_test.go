// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/internal/gen"
)

type refreshFlowTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
}

func TestPublicClientPKCERefreshTokenReplay(t *testing.T) {
	verifier := strings.Repeat("verify-me-", 8)

	for _, tc := range []struct {
		description string
		provider    func() fosite.OAuth2Provider
	}{
		{
			description: "ComposeAllEnabled",
			provider: func() fosite.OAuth2Provider {
				config := new(fosite.Config)
				config.EnforcePKCE = true
				config.EnablePKCEPlainChallengeMethod = true
				config.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
				return compose.ComposeAllEnabled(config, fositeStore, gen.MustRSAKey())
			},
		},
		{
			description: "OAuth2 factories",
			provider: func() fosite.OAuth2Provider {
				config := new(fosite.Config)
				config.EnforcePKCE = true
				config.EnablePKCEPlainChallengeMethod = true
				return compose.Compose(
					config,
					fositeStore,
					hmacStrategy,
					compose.OAuth2AuthorizeExplicitFactory,
					compose.OAuth2PKCEFactory,
					compose.OAuth2RefreshTokenGrantFactory,
					compose.OAuth2TokenIntrospectionFactory,
				)
			},
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			provider := tc.provider()
			ts := mockServer(t, provider, &fosite.DefaultSession{})
			defer ts.Close()

			fositeStore.Clients["public-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

			authURL := ts.URL + "/auth?" + url.Values{
				"response_type":         {"code"},
				"client_id":             {"public-client"},
				"redirect_uri":          {ts.URL + "/callback"},
				"scope":                 {"offline"},
				"state":                 {"1234567890"},
				"code_challenge":        {verifier},
				"code_challenge_method": {"plain"},
			}.Encode()

			code := authorizeCodeForRefreshFlow(t, authURL)

			initial := exchangeAuthorizationCode(t, ts.URL+tokenRelativePath, code, verifier, ts.URL+"/callback")
			require.NotEmpty(t, initial.AccessToken)
			require.NotEmpty(t, initial.RefreshToken)

			firstRefresh := refreshTokenForFlow(t, ts.URL+tokenRelativePath, initial.RefreshToken, http.StatusOK)
			require.NotEmpty(t, firstRefresh.AccessToken)
			require.NotEmpty(t, firstRefresh.RefreshToken)
			require.NotEqual(t, initial.RefreshToken, firstRefresh.RefreshToken)

			secondRefresh := refreshTokenForFlow(t, ts.URL+tokenRelativePath, firstRefresh.RefreshToken, http.StatusOK)
			require.NotEmpty(t, secondRefresh.AccessToken)
			require.NotEmpty(t, secondRefresh.RefreshToken)

			require.True(t, accessTokenIsActive(t, ts, secondRefresh.AccessToken), "the latest access token must be active")

			// Replaying the earliest refresh token is rejected and revokes the
			// whole token family.
			replay := refreshTokenForFlow(t, ts.URL+tokenRelativePath, initial.RefreshToken, http.StatusBadRequest)
			require.Empty(t, replay.AccessToken)
			assert.Equal(t, "invalid_grant", replay.Error)

			require.False(t, accessTokenIsActive(t, ts, secondRefresh.AccessToken), "the second refresh access token must be inactive after replay detection")
			require.False(t, accessTokenIsActive(t, ts, firstRefresh.AccessToken))
			require.False(t, accessTokenIsActive(t, ts, initial.AccessToken))
		})
	}
}

func authorizeCodeForRefreshFlow(t *testing.T, authURL string) string {
	t.Helper()

	resp, err := http.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	code := resp.Request.URL.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func exchangeAuthorizationCode(t *testing.T, tokenURL, code, verifier, redirectURI string) refreshFlowTokenResponse {
	t.Helper()

	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"public-client"},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var token refreshFlowTokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&token))
	return token
}

func refreshTokenForFlow(t *testing.T, tokenURL, refreshToken string, expectedStatus int) refreshFlowTokenResponse {
	t.Helper()

	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"public-client"},
	})
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected token endpoint status: got %d, want %d, body: %s", resp.StatusCode, expectedStatus, body)
	}

	var token refreshFlowTokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&token))
	return token
}

func accessTokenIsActive(t *testing.T, ts *httptest.Server, token string) bool {
	t.Helper()

	req, err := http.NewRequest("POST", ts.URL+"/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	req.SetBasicAuth("my-client", "foobar")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.Active
}
