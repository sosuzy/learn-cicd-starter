package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	// Test case: No Authorization header
	t.Run("No Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		apiKey, err := GetAPIKey(headers)

		assert.Empty(t, apiKey)
		assert.ErrorIs(t, err, ErrNoAuthHeaderIncluded)
	})

	// Test case: Malformed Authorization header (e.g., missing API key)
	t.Run("Malformed Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer some_token")

		apiKey, err := GetAPIKey(headers)

		assert.Empty(t, apiKey)
		assert.Error(t, err)
		assert.EqualError(t, err, "malformed authorization header")
	})

	// Test case: Valid Authorization header
	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey abc123")

		apiKey, err := GetAPIKey(headers)

		assert.NoError(t, err)
		assert.Equal(t, "abc123", apiKey)
	})

	// Test case: Missing API Key in Authorization header
	t.Run("Missing API Key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)

		assert.Empty(t, apiKey)
		assert.Error(t, err)
		assert.EqualError(t, err, "malformed authorization header")
	})
}
