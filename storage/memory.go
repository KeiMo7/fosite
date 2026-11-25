// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

type MemoryUserRelation struct {
	Username string
	Password string
}

type IssuerPublicKeys struct {
	Issuer    string
	KeysBySub map[string]SubjectPublicKeys
}

type SubjectPublicKeys struct {
	Subject string
	Keys    map[string]PublicKeyScopes
}

type PublicKeyScopes struct {
	Key    *jose.JSONWebKey
	Scopes []string
}

type DeviceAuthPair struct {
	d string
	u string
}

type MemoryStore struct {
	Clients         map[string]fosite.Client
	AuthorizeCodes  map[string]StoreAuthorizeCode
	IDSessions      map[string]fosite.Requester
	AccessTokens    map[string]fosite.Requester
	RefreshTokens   map[string]StoreRefreshToken
	DeviceAuths     map[string]fosite.DeviceRequester
	PKCES           map[string]fosite.Requester
	Users           map[string]MemoryUserRelation
	BlacklistedJTIs map[string]time.Time
	// In-memory request ID to token signatures
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string
	DeviceCodesRequestIDs  map[string]DeviceAuthPair
	UserCodesRequestIDs    map[string]string
	// Public keys to check signature in auth grant jwt assertion.
	IssuerPublicKeys map[string]IssuerPublicKeys
	PARSessions      map[string]fosite.AuthorizeRequester

	// Token family indexes. They map a request ID to every token signature
	// that was ever issued for it, so that revoking a request ID revokes the
	// whole token family instead of only the latest signature. The indexes are
	// guarded by accessTokenRequestIDsMutex and refreshTokenRequestIDsMutex
	// respectively, always acquired before the token tables.
	accessTokenFamilies  map[string]map[string]struct{}
	refreshTokenFamilies map[string]map[string]struct{}

	clientsMutex                sync.RWMutex
	authorizeCodesMutex         sync.RWMutex
	idSessionsMutex             sync.RWMutex
	accessTokensMutex           sync.RWMutex
	refreshTokensMutex          sync.RWMutex
	deviceAuthsMutex            sync.RWMutex
	pkcesMutex                  sync.RWMutex
	usersMutex                  sync.RWMutex
	blacklistedJTIsMutex        sync.RWMutex
	accessTokenRequestIDsMutex  sync.RWMutex
	refreshTokenRequestIDsMutex sync.RWMutex
	deviceAuthsRequestIDsMutex  sync.RWMutex
	issuerPublicKeysMutex       sync.RWMutex
	parSessionsMutex            sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:                make(map[string]fosite.Client),
		AuthorizeCodes:         make(map[string]StoreAuthorizeCode),
		IDSessions:             make(map[string]fosite.Requester),
		AccessTokens:           make(map[string]fosite.Requester),
		RefreshTokens:          make(map[string]StoreRefreshToken),
		DeviceAuths:            make(map[string]fosite.DeviceRequester),
		PKCES:                  make(map[string]fosite.Requester),
		Users:                  make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:  make(map[string]string),
		RefreshTokenRequestIDs: make(map[string]string),
		DeviceCodesRequestIDs:  make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:    make(map[string]string),
		BlacklistedJTIs:        make(map[string]time.Time),
		IssuerPublicKeys:       make(map[string]IssuerPublicKeys),
		PARSessions:            make(map[string]fosite.AuthorizeRequester),
	}
}

type StoreAuthorizeCode struct {
	active bool
	fosite.Requester
}

type StoreRefreshToken struct {
	active               bool
	accessTokenSignature string
	fosite.Requester
}

func NewExampleStore() *MemoryStore {
	return &MemoryStore{
		IDSessions: make(map[string]fosite.Requester),
		Clients: map[string]fosite.Client{
			"my-client": &fosite.DefaultClient{
				ID:             "my-client",
				Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
				RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
			"custom-lifespan-client": &fosite.DefaultClientWithCustomTokenLifespans{
				DefaultClient: &fosite.DefaultClient{
					ID:             "custom-lifespan-client",
					Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
					RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
					RedirectURIs:   []string{"http://localhost:3846/callback"},
					ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
					GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
					Scopes:         []string{"fosite", "openid", "photos", "offline"},
				},
				TokenLifespans: &internal.TestLifespans,
			},
			"encoded:client": &fosite.DefaultClient{
				ID:             "encoded:client",
				Secret:         []byte(`$2a$10$A7M8b65dSSKGHF0H2sNkn.9Z0hT8U1Nv6OWPV3teUUaczXkVkxuDS`), // = "encoded&password"
				RotatedSecrets: nil,
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
		},
		Users: map[string]MemoryUserRelation{
			"peter": {
				// This store simply checks for equality, a real storage implementation would obviously use
				// a hashing algorithm for encrypting the user password.
				Username: "peter",
				Password: "secret",
			},
		},
		AuthorizeCodes:         map[string]StoreAuthorizeCode{},
		AccessTokens:           map[string]fosite.Requester{},
		RefreshTokens:          map[string]StoreRefreshToken{},
		PKCES:                  map[string]fosite.Requester{},
		DeviceAuths:            make(map[string]fosite.DeviceRequester),
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
		DeviceCodesRequestIDs:  make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:    make(map[string]string),
		IssuerPublicKeys:       map[string]IssuerPublicKeys{},
		PARSessions:            map[string]fosite.AuthorizeRequester{},
	}
}

func (s *MemoryStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *MemoryStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.idSessionsMutex.RLock()
	defer s.idSessionsMutex.RUnlock()

	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	delete(s.IDSessions, authorizeCode)
	return nil
}

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	if client, ok := s.Clients[clientID]; ok {
		if clc, ok := client.(*fosite.DefaultClientWithCustomTokenLifespans); ok {
			clc.SetTokenLifespans(lifespans)
			return nil
		}
		return fosite.ErrorToRFC6749Error(errors.New("failed to set token lifespans due to failed client type assertion"))
	}
	return fosite.ErrNotFound
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.blacklistedJTIsMutex.RLock()
	defer s.blacklistedJTIsMutex.RUnlock()

	if exp, exists := s.BlacklistedJTIs[jti]; exists && exp.After(time.Now()) {
		return fosite.ErrJTIKnown
	}

	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.blacklistedJTIsMutex.Lock()
	defer s.blacklistedJTIsMutex.Unlock()

	// delete expired jtis
	for j, e := range s.BlacklistedJTIs {
		if e.Before(time.Now()) {
			delete(s.BlacklistedJTIs, j)
		}
	}

	if _, exists := s.BlacklistedJTIs[jti]; exists {
		return fosite.ErrJTIKnown
	}

	s.BlacklistedJTIs[jti] = exp
	return nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.authorizeCodesMutex.RLock()
	defer s.authorizeCodesMutex.RUnlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInvalidatedAuthorizeCode
	}

	return rel.Requester, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return fosite.ErrNotFound
	}
	rel.active = false
	s.AuthorizeCodes[code] = rel
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	s.PKCES[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.pkcesMutex.RLock()
	defer s.pkcesMutex.RUnlock()

	rel, ok := s.PKCES[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	delete(s.PKCES, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	// We first lock accessTokenRequestIDsMutex and then accessTokensMutex because this is the same order
	// locking happens in RevokeAccessToken and using the same order prevents deadlocks.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	if s.AccessTokenRequestIDs == nil {
		s.AccessTokenRequestIDs = make(map[string]string)
	}
	if s.AccessTokens == nil {
		s.AccessTokens = make(map[string]fosite.Requester)
	}
	if s.accessTokenFamilies == nil {
		s.accessTokenFamilies = make(map[string]map[string]struct{})
	}

	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[req.GetID()] = signature
	s.addAccessTokenToFamily(req.GetID(), signature)
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.accessTokensMutex.RLock()
	defer s.accessTokensMutex.RUnlock()

	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	// The family index is locked first to match the lock ordering used by
	// CreateAccessTokenSession and RevokeAccessToken.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	s.deleteAccessTokenSessionLocked(signature)
	return nil
}

// deleteAccessTokenSessionLocked removes an access token and its family index
// entry. The caller must hold accessTokenRequestIDsMutex and accessTokensMutex.
func (s *MemoryStore) deleteAccessTokenSessionLocked(signature string) {
	delete(s.AccessTokens, signature)
	for requestID, signatures := range s.accessTokenFamilies {
		if _, ok := signatures[signature]; !ok {
			continue
		}
		delete(signatures, signature)
		if len(signatures) == 0 {
			delete(s.accessTokenFamilies, requestID)
		}
	}
}

// addAccessTokenToFamily registers a signature in the token family of requestID.
// The caller must hold accessTokenRequestIDsMutex.
func (s *MemoryStore) addAccessTokenToFamily(requestID, signature string) {
	signatures, ok := s.accessTokenFamilies[requestID]
	if !ok {
		signatures = make(map[string]struct{})
		s.accessTokenFamilies[requestID] = signatures
	}
	signatures[signature] = struct{}{}
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in RevokeRefreshToken and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	if s.RefreshTokenRequestIDs == nil {
		s.RefreshTokenRequestIDs = make(map[string]string)
	}
	if s.RefreshTokens == nil {
		s.RefreshTokens = make(map[string]StoreRefreshToken)
	}
	if s.refreshTokenFamilies == nil {
		s.refreshTokenFamilies = make(map[string]map[string]struct{})
	}

	s.RefreshTokens[signature] = StoreRefreshToken{active: true, Requester: req, accessTokenSignature: accessTokenSignature}
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	s.addRefreshTokenToFamily(req.GetID(), signature)
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.refreshTokensMutex.RLock()
	defer s.refreshTokensMutex.RUnlock()

	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInactiveToken
	}
	return rel, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	// The family index is locked first to match the lock ordering used by
	// CreateRefreshTokenSession and RevokeRefreshToken.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	s.deleteRefreshTokenSessionLocked(signature)
	return nil
}

// deleteRefreshTokenSessionLocked removes a refresh token and its family index
// entry. The caller must hold refreshTokenRequestIDsMutex and
// refreshTokensMutex.
func (s *MemoryStore) deleteRefreshTokenSessionLocked(signature string) {
	delete(s.RefreshTokens, signature)
	for requestID, signatures := range s.refreshTokenFamilies {
		if _, ok := signatures[signature]; !ok {
			continue
		}
		delete(signatures, signature)
		if len(signatures) == 0 {
			delete(s.refreshTokenFamilies, requestID)
		}
	}
}

// addRefreshTokenToFamily registers a signature in the token family of
// requestID. The caller must hold refreshTokenRequestIDsMutex.
func (s *MemoryStore) addRefreshTokenToFamily(requestID, signature string) {
	signatures, ok := s.refreshTokenFamilies[requestID]
	if !ok {
		signatures = make(map[string]struct{})
		s.refreshTokenFamilies[requestID] = signatures
	}
	signatures[signature] = struct{}{}
}

func (s *MemoryStore) Authenticate(_ context.Context, name string, secret string) (subject string, err error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	rel, ok := s.Users[name]
	if !ok {
		return "", fosite.ErrNotFound
	}
	if rel.Password != secret {
		return "", fosite.ErrNotFound.WithDebug("Invalid credentials")
	}
	return uuid.New().String(), nil
}

func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in CreateRefreshTokenSession and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	// Revoke every refresh token that was ever issued for this request ID, not
	// only the most recent one. Unknown request IDs are a no-op.
	signatures := make(map[string]struct{}, len(s.refreshTokenFamilies[requestID])+1)
	for signature := range s.refreshTokenFamilies[requestID] {
		signatures[signature] = struct{}{}
	}
	if signature, ok := s.RefreshTokenRequestIDs[requestID]; ok {
		signatures[signature] = struct{}{}
	}

	for signature := range signatures {
		rel, ok := s.RefreshTokens[signature]
		if !ok {
			continue
		}
		rel.active = false
		s.RefreshTokens[signature] = rel
	}
	return nil
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	// Lock order: request ID index first, token table second. This matches
	// CreateAccessTokenSession and DeleteAccessTokenSession.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	// Revoke every access token that was ever issued for this request ID, not
	// only the most recent one. Unknown request IDs are a no-op.
	for signature := range s.accessTokenFamilies[requestID] {
		delete(s.AccessTokens, signature)
	}
	if signature, ok := s.AccessTokenRequestIDs[requestID]; ok {
		delete(s.AccessTokens, signature)
	}
	delete(s.accessTokenFamilies, requestID)
	return nil
}

func (s *MemoryStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Key, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if len(subKeys.Keys) == 0 {
				return nil, fosite.ErrNotFound
			}

			keys := make([]jose.JSONWebKey, 0, len(subKeys.Keys))
			for _, keyScopes := range subKeys.Keys {
				keys = append(keys, *keyScopes.Key)
			}

			return &jose.JSONWebKeySet{Keys: keys}, nil
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Scopes, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := s.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (s *MemoryStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
func (s *MemoryStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	s.PARSessions[requestURI] = request
	return nil
}

// GetPARSession gets the push authorization request context. If the request is nil, a new request object
// is created. Otherwise, the same object is updated.
func (s *MemoryStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	s.parSessionsMutex.RLock()
	defer s.parSessionsMutex.RUnlock()

	r, ok := s.PARSessions[requestURI]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	return r, nil
}

// DeletePARSession deletes the context.
func (s *MemoryStore) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	delete(s.PARSessions, requestURI)
	return nil
}

// RotateRefreshToken consumes the presented refresh token exactly once. It
// marks the token inactive and removes the access token that was issued
// alongside it, so that a refresh token can only be exchanged a single time.
//
// The refresh token must exist, belong to requestID, still be active and still
// be the current token of that request. When another request has already
// consumed it, ErrSerializationFailure is returned so the caller can ask the
// client to retry.
func (s *MemoryStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// Lock order: refresh request ID index, refresh token table, and only then
	// the access token table. No code path acquires these locks in reverse
	// order.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	if len(refreshTokenSignature) == 0 {
		return fosite.ErrNotFound
	}

	rel, ok := s.RefreshTokens[refreshTokenSignature]
	if !ok {
		return fosite.ErrNotFound
	}
	if !rel.active {
		return fosite.ErrSerializationFailure
	}
	if rel.Requester == nil || rel.GetID() != requestID {
		return fosite.ErrNotFound
	}
	if current, ok := s.RefreshTokenRequestIDs[requestID]; !ok || current != refreshTokenSignature {
		return fosite.ErrSerializationFailure
	}

	rel.active = false
	s.RefreshTokens[refreshTokenSignature] = rel

	if len(rel.accessTokenSignature) > 0 {
		s.accessTokensMutex.Lock()
		defer s.accessTokensMutex.Unlock()

		// Only the presented refresh token and the access token it was paired
		// with are consumed. The family index is intentionally left alone:
		// the signature is unique, and removing stale entries from the index
		// would require taking the request ID mutex out of the established
		// lock order.
		delete(s.AccessTokens, rel.accessTokenSignature)
	}

	return nil
}

// CreateDeviceAuthSession stores the device auth session
func (s *MemoryStore) CreateDeviceAuthSession(_ context.Context, deviceCodeSignature, userCodeSignature string, req fosite.DeviceRequester) error {
	s.deviceAuthsRequestIDsMutex.Lock()
	defer s.deviceAuthsRequestIDsMutex.Unlock()
	s.deviceAuthsMutex.Lock()
	defer s.deviceAuthsMutex.Unlock()

	s.DeviceAuths[deviceCodeSignature] = req
	s.DeviceAuths[userCodeSignature] = req
	s.DeviceCodesRequestIDs[req.GetID()] = DeviceAuthPair{d: deviceCodeSignature, u: userCodeSignature}
	return nil
}

// GetDeviceCodeSession gets the device code session
func (s *MemoryStore) GetDeviceCodeSession(_ context.Context, signature string, _ fosite.Session) (fosite.DeviceRequester, error) {
	s.deviceAuthsMutex.RLock()
	defer s.deviceAuthsMutex.RUnlock()

	rel, ok := s.DeviceAuths[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

// InvalidateDeviceCodeSession invalidates the device code session
func (s *MemoryStore) InvalidateDeviceCodeSession(_ context.Context, code string) error {
	s.deviceAuthsMutex.Lock()
	defer s.deviceAuthsMutex.Unlock()

	delete(s.DeviceAuths, code)
	return nil
}
