// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validVerifier returns a verifier of the requested length drawn from the
// allowed alphabet.
func validVerifier(length int) string {
	return seededVerifier(0, length)
}

// seededVerifier returns a deterministic verifier of the requested length,
// varying the content with seed.
func seededVerifier(seed, length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteByte(alphabet[(seed+i)%len(alphabet)])
	}
	return b.String()
}

func TestParseChallengeMethod(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected ChallengeMethod
		ok       bool
	}{
		{name: "s256", input: "S256", expected: ChallengeMethodS256, ok: true},
		{name: "plain", input: "plain", expected: ChallengeMethodPlain, ok: true},
		{name: "empty defaults to plain", input: "", expected: ChallengeMethodPlain, ok: true},
		{name: "lowercase s256", input: "s256"},
		{name: "mixed case s256", input: "S256x"},
		{name: "mixed case plain", input: "Plain"},
		{name: "leading space", input: " S256"},
		{name: "trailing space", input: "S256 "},
		{name: "unknown", input: "SHA256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method, err := ParseChallengeMethod(tc.input)
			if !tc.ok {
				require.ErrorIs(t, err, ErrMethodUnsupported)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, method)
		})
	}
}

func TestParseCodeChallengeS256(t *testing.T) {
	valid := validVerifier(MinCodeVerifierLength)
	canonical, err := S256Challenge(valid)
	require.NoError(t, err)
	require.Len(t, canonical, 43)

	// A 43 character challenge with non-zero trailing bits: the final
	// character is changed to one that decodes to the same 32 bytes with
	// non-zero unused bits is hard to construct generically, so build one
	// explicitly. "AAAA...AB" decodes to 32 bytes with a non-zero trailing
	// bit pattern that does not re-encode to itself.
	nonZeroTailBits := strings.Repeat("A", 42) + "B"
	require.NotEqual(t, canonical, nonZeroTailBits)
	if decoded, derr := base64.RawURLEncoding.Strict().DecodeString(nonZeroTailBits); derr == nil {
		require.NotEqual(t, nonZeroTailBits, base64.RawURLEncoding.EncodeToString(decoded))
	}

	for _, tc := range []struct {
		name      string
		challenge string
		expected  error
	}{
		{name: "canonical", challenge: canonical},
		{name: "42 chars", challenge: canonical[:42], expected: ErrChallengeMalformed},
		{name: "44 chars", challenge: canonical + "A", expected: ErrChallengeMalformed},
		{name: "empty", challenge: "", expected: ErrChallengeMissing},
		{name: "padding", challenge: canonical[:42] + "=", expected: ErrChallengeMalformed},
		{name: "plus", challenge: canonical[:42] + "+", expected: ErrChallengeMalformed},
		{name: "slash", challenge: canonical[:42] + "/", expected: ErrChallengeMalformed},
		{name: "whitespace", challenge: canonical[:42] + " ", expected: ErrChallengeMalformed},
		{name: "newline", challenge: canonical[:42] + "\n", expected: ErrChallengeMalformed},
		{name: "full width", challenge: canonical[:42] + "Ａ", expected: ErrChallengeMalformed},
		{name: "non-zero tail bits", challenge: nonZeroTailBits, expected: ErrChallengeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := ParseCodeChallenge(ChallengeMethodS256, tc.challenge)
			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)
				if len(tc.challenge) > 0 {
					assert.NotContains(t, err.Error(), tc.challenge)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ChallengeMethodS256, challenge.Method())
			assert.Equal(t, tc.challenge, challenge.Value())
		})
	}
}

func TestParseCodeChallengePlain(t *testing.T) {
	for _, tc := range []struct {
		name      string
		challenge string
		expected  error
	}{
		{name: "43 chars", challenge: validVerifier(43)},
		{name: "128 chars", challenge: validVerifier(128)},
		{name: "42 chars", challenge: validVerifier(42), expected: ErrChallengeMalformed},
		{name: "129 chars", challenge: validVerifier(129), expected: ErrChallengeMalformed},
		{name: "empty", challenge: "", expected: ErrChallengeMissing},
		{name: "invalid character", challenge: validVerifier(42) + "!", expected: ErrChallengeMalformed},
		{name: "full width", challenge: validVerifier(42) + "Ａ", expected: ErrChallengeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := ParseCodeChallenge(ChallengeMethodPlain, tc.challenge)
			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)
				if len(tc.challenge) > 0 {
					assert.NotContains(t, err.Error(), tc.challenge)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ChallengeMethodPlain, challenge.Method())
			assert.Equal(t, tc.challenge, challenge.Value())
		})
	}

	t.Run("empty method defaults to plain", func(t *testing.T) {
		challenge, err := ParseCodeChallenge("", validVerifier(43))
		require.NoError(t, err)
		assert.Equal(t, ChallengeMethodPlain, challenge.Method())
	})

	t.Run("unsupported method", func(t *testing.T) {
		_, err := ParseCodeChallenge("s256", validVerifier(43))
		require.ErrorIs(t, err, ErrMethodUnsupported)
	})
}

func TestS256RoundTrip(t *testing.T) {
	// 200 verifiers of lengths 43 to 128 must round-trip through the canonical
	// challenge representation.
	for i := 0; i < 200; i++ {
		length := MinCodeVerifierLength + i%(MaxCodeVerifierLength-MinCodeVerifierLength+1)
		verifier := seededVerifier(i, length)

		challenge, err := S256Challenge(verifier)
		require.NoError(t, err)
		require.Len(t, challenge, 43)
		assert.NotContains(t, challenge, "=")

		parsed, err := ParseCodeChallenge(ChallengeMethodS256, challenge)
		require.NoError(t, err)
		require.NoError(t, parsed.Verify(verifier))
	}
}

func TestS256ChallengeRejectsInvalidVerifier(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verifier string
		expected error
	}{
		{name: "empty", verifier: "", expected: ErrVerifierMissing},
		{name: "too short", verifier: validVerifier(42), expected: ErrVerifierMalformed},
		{name: "too long", verifier: validVerifier(129), expected: ErrVerifierMalformed},
		{name: "invalid character", verifier: validVerifier(42) + "!", expected: ErrVerifierMalformed},
		{name: "full width", verifier: validVerifier(42) + "Ａ", expected: ErrVerifierMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := S256Challenge(tc.verifier)
			require.ErrorIs(t, err, tc.expected)
			assert.Empty(t, challenge)
			if len(tc.verifier) > 0 {
				assert.NotContains(t, err.Error(), tc.verifier)
			}
		})
	}
}

func TestVerifyMismatch(t *testing.T) {
	verifier := validVerifier(64)
	challenge, err := S256Challenge(verifier)
	require.NoError(t, err)

	parsed, err := ParseCodeChallenge(ChallengeMethodS256, challenge)
	require.NoError(t, err)

	for i := 0; i < len(challenge); i++ {
		mutated := []byte(challenge)
		if i == len(challenge)-1 {
			// The final base64url character carries padding bits. Only use
			// characters with zero trailing bits so that the mutated challenge
			// is still a canonical encoding and reaches the comparison.
			const canonicalTail = "AEIMQUYcgkosw048"
			replacement := canonicalTail[0]
			if mutated[i] == replacement {
				replacement = canonicalTail[1]
			}
			mutated[i] = replacement
		} else if mutated[i] == 'A' {
			mutated[i] = 'B'
		} else {
			mutated[i] = 'A'
		}

		mutatedChallenge, err := ParseCodeChallenge(ChallengeMethodS256, string(mutated))
		require.NoError(t, err)
		require.ErrorIs(t, mutatedChallenge.Verify(verifier), ErrVerifierMismatch)
	}

	require.NoError(t, parsed.Verify(verifier))
	require.ErrorIs(t, parsed.Verify(validVerifier(65)), ErrVerifierMismatch)
}

func TestVerifyRejectsInvalidVerifier(t *testing.T) {
	challenge, err := ParseCodeChallenge(ChallengeMethodPlain, validVerifier(50))
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		verifier string
		expected error
	}{
		{name: "empty", verifier: "", expected: ErrVerifierMissing},
		{name: "too short", verifier: validVerifier(42), expected: ErrVerifierMalformed},
		{name: "too long", verifier: validVerifier(129), expected: ErrVerifierMalformed},
		{name: "invalid character", verifier: validVerifier(42) + "/", expected: ErrVerifierMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := challenge.Verify(tc.verifier)
			require.ErrorIs(t, err, tc.expected)
			if len(tc.verifier) > 0 {
				assert.NotContains(t, err.Error(), tc.verifier)
			}
		})
	}
}

func TestVerifyMalformedStoredChallenge(t *testing.T) {
	verifier := validVerifier(50)

	// A structurally broken stored challenge must be reported as a mismatch
	// rather than panicking or leaking the challenge.
	for _, tc := range []struct {
		name      string
		challenge CodeChallenge
		expected  error
	}{
		{name: "s256 with 96 chars", challenge: CodeChallenge{method: ChallengeMethodS256, value: strings.Repeat("a", 96)}},
		{name: "plain too short", challenge: CodeChallenge{method: ChallengeMethodPlain, value: "not-foo"}},
		{name: "unknown method", challenge: CodeChallenge{method: "unknown", value: validVerifier(50)}, expected: ErrMethodUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.challenge.Verify(verifier)
			expected := tc.expected
			if expected == nil {
				expected = ErrVerifierMismatch
			}
			require.ErrorIs(t, err, expected)
			assert.NotContains(t, err.Error(), tc.challenge.value)
		})
	}
}

func TestVerifierErrorOrder(t *testing.T) {
	// Every step of verification returns exactly one sentinel, in the order
	// length, character set, challenge structure, comparison.
	short := "short"
	require.ErrorIs(t, func() error {
		c, err := ParseCodeChallenge(ChallengeMethodS256, "challenge")
		require.ErrorIs(t, err, ErrChallengeMalformed)
		return c.Verify(short)
	}(), ErrVerifierMalformed)

	malformed := strings.Repeat("!", MinCodeVerifierLength)
	require.ErrorIs(t, CodeChallenge{method: ChallengeMethodS256, value: "bad"}.Verify(malformed), ErrVerifierMalformed)

	require.ErrorIs(t, CodeChallenge{method: ChallengeMethodS256, value: "bad"}.Verify(validVerifier(43)), ErrVerifierMismatch)
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrChallengeMissing,
		ErrChallengeMalformed,
		ErrMethodUnsupported,
		ErrVerifierMissing,
		ErrVerifierMalformed,
		ErrVerifierMismatch,
	}
	for i := range sentinels {
		for j := range sentinels {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(sentinels[i], sentinels[j]))
		}
	}
}
