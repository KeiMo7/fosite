// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// Code verifier lengths as defined by RFC 7636, Section 4.1.
const (
	MinCodeVerifierLength = 43
	MaxCodeVerifierLength = 128
)

// Sentinel errors returned by the PKCE parsing and verification helpers. Errors
// never contain the submitted verifier or challenge, callers can match them
// using errors.Is.
var (
	ErrChallengeMissing   = errors.New("pkce: code challenge is missing")
	ErrChallengeMalformed = errors.New("pkce: code challenge is malformed")
	ErrMethodUnsupported  = errors.New("pkce: code challenge method is unsupported")
	ErrVerifierMissing    = errors.New("pkce: code verifier is missing")
	ErrVerifierMalformed  = errors.New("pkce: code verifier is malformed")
	ErrVerifierMismatch   = errors.New("pkce: code verifier does not match the code challenge")
)

// Aliases that name the specific verifier rule which was violated. They all
// refer to ErrVerifierMalformed, so errors.Is keeps matching regardless of
// which name a caller uses.
var (
	ErrVerifierInvalidLength     = ErrVerifierMalformed
	ErrVerifierInvalidCharacters = ErrVerifierMalformed
	ErrVerifierTooShort          = ErrVerifierMalformed
	ErrVerifierTooLong           = ErrVerifierMalformed
)

// ChallengeMethod is the transformation applied to a code verifier before it is
// sent to the authorization endpoint.
type ChallengeMethod string

const (
	ChallengeMethodS256  ChallengeMethod = "S256"
	ChallengeMethodPlain ChallengeMethod = "plain"
)

// ParseChallengeMethod parses a code_challenge_method request parameter. An
// absent method defaults to "plain" as defined by RFC 7636, Section 4.2. Only
// the exact literals "S256" and "plain" are accepted.
func ParseChallengeMethod(raw string) (ChallengeMethod, error) {
	switch raw {
	case "":
		return ChallengeMethodPlain, nil
	case string(ChallengeMethodS256):
		return ChallengeMethodS256, nil
	case string(ChallengeMethodPlain):
		return ChallengeMethodPlain, nil
	default:
		return "", ErrMethodUnsupported
	}
}

// CodeChallenge is a parsed code_challenge bound to its challenge method.
type CodeChallenge struct {
	method ChallengeMethod
	value  string
}

// Method returns the transformation method of the challenge.
func (c CodeChallenge) Method() ChallengeMethod {
	return c.method
}

// Value returns the canonical challenge value.
func (c CodeChallenge) Value() string {
	return c.value
}

// ParseCodeChallenge validates the structure of a code_challenge and returns
// the parsed challenge. The challenge must be canonical: for S256 it is a
// 43-character base64url encoded SHA-256 digest without padding, for plain it
// is a string between 43 and 128 characters using the code verifier alphabet.
func ParseCodeChallenge(method ChallengeMethod, challenge string) (CodeChallenge, error) {
	if len(challenge) == 0 {
		return CodeChallenge{}, ErrChallengeMissing
	}

	normalized, err := normalizeChallengeMethod(method)
	if err != nil {
		return CodeChallenge{}, err
	}

	switch normalized {
	case ChallengeMethodS256:
		if err := validateS256Challenge(challenge); err != nil {
			return CodeChallenge{}, err
		}
	case ChallengeMethodPlain:
		if err := validatePlainChallenge(challenge); err != nil {
			return CodeChallenge{}, err
		}
	}

	return CodeChallenge{method: normalized, value: challenge}, nil
}

// Verify checks that the code verifier produces the challenge. The verifier is
// validated before the stored challenge is inspected and compared in constant
// time.
func (c CodeChallenge) Verify(verifier string) error {
	if err := validateCodeVerifier(verifier); err != nil {
		return err
	}

	method, err := normalizeChallengeMethod(c.method)
	if err != nil {
		return err
	}

	var expected string
	switch method {
	case ChallengeMethodS256:
		if err := validateS256Challenge(c.value); err != nil {
			return ErrVerifierMismatch
		}
		expected = s256Digest(verifier)
	case ChallengeMethodPlain:
		if err := validatePlainChallenge(c.value); err != nil {
			return ErrVerifierMismatch
		}
		expected = verifier
	}

	if subtle.ConstantTimeCompare([]byte(expected), []byte(c.value)) != 1 {
		return ErrVerifierMismatch
	}

	return nil
}

// S256Challenge derives the canonical S256 code challenge for a code verifier.
// The verifier must satisfy the length and character requirements of RFC 7636.
func S256Challenge(verifier string) (string, error) {
	if err := validateCodeVerifier(verifier); err != nil {
		return "", err
	}
	return s256Digest(verifier), nil
}

// s256Digest returns BASE64URL-ENCODE(SHA256(ASCII(verifier))). It does not
// validate the verifier and must only be called with a verifier that already
// passed validateCodeVerifier.
func s256Digest(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func normalizeChallengeMethod(method ChallengeMethod) (ChallengeMethod, error) {
	if method == "" {
		return ChallengeMethodPlain, nil
	}
	if _, err := ParseChallengeMethod(string(method)); err != nil {
		return "", err
	}
	return method, nil
}

// validateCodeVerifier enforces the verifier rules in their fixed order: length
// first, then character set.
func validateCodeVerifier(verifier string) error {
	if len(verifier) == 0 {
		return ErrVerifierMissing
	}
	if len(verifier) < MinCodeVerifierLength || len(verifier) > MaxCodeVerifierLength {
		return ErrVerifierMalformed
	}
	if !isCodeVerifierString(verifier) {
		return ErrVerifierMalformed
	}
	return nil
}

func validatePlainChallenge(challenge string) error {
	if len(challenge) < MinCodeVerifierLength || len(challenge) > MaxCodeVerifierLength {
		return ErrChallengeMalformed
	}
	if !isCodeVerifierString(challenge) {
		return ErrChallengeMalformed
	}
	return nil
}

func validateS256Challenge(challenge string) error {
	// A SHA-256 digest is 32 bytes which base64url encodes to exactly 43
	// characters without padding.
	if len(challenge) != 43 {
		return ErrChallengeMalformed
	}
	for i := 0; i < len(challenge); i++ {
		if !isBase64URLCharacter(challenge[i]) {
			return ErrChallengeMalformed
		}
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(decoded) != sha256.Size {
		return ErrChallengeMalformed
	}

	// Reject non-canonical encodings, for example non-zero trailing bits.
	// The comparison is done in constant time even though the challenge is
	// public data.
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(decoded)), []byte(challenge)) != 1 {
		return ErrChallengeMalformed
	}

	return nil
}

func isCodeVerifierString(value string) bool {
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '.' || char == '_' || char == '~' {
			continue
		}
		return false
	}
	return true
}

func isBase64URLCharacter(char byte) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_'
}
