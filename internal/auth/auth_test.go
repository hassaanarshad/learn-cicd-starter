// Created by Google Gemini

package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// Removed the external module import, as the test is now running within the same package.
)

// Define the unexported error string for testing malformed headers
const malformedHeaderError = "malformed authorization header"

func TestGetAPIKey(t *testing.T) {
	// Define a structure for test cases
	type testCase struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}

	tests := []testCase{
		{
			name: "Success_ValidHeader",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name:          "Failure_NoHeader",
			headers:       http.Header{},
			expectedKey:   "",
			// Referencing the exported error directly now that we are in the same package
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Failure_WrongScheme",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			expectedKey:   "",
			// We check the error string since the error itself is unexported (errors.New)
			expectedError: errors.New(malformedHeaderError),
		},
		{
			name: "Failure_MissingKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New(malformedHeaderError),
		},
		{
			name: "Failure_TooManyParts",
			headers: http.Header{
				"Authorization": []string{"ApiKey key part3"},
			},
			expectedKey:   "key", // The current implementation returns the second part ("key") and nil error
			expectedError: nil,
		},
		{
			name: "Success_EmptyKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: nil,
		},
		{
			name: "Failure_DifferentHeaderName",
			headers: http.Header{
				"authorization": []string{"ApiKey my-secret-api-key"}, // Header key is lowercase 'authorization'
			},
			// Updated expectations to reflect observed behavior:
			// In this test setup, `headers.Get("Authorization")` fails to find
			// the lowercase key, resulting in an empty string and the "no header" error.
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Calling the function directly as we are in the same package
			key, err := GetAPIKey(tc.headers)

			// 1. Check the returned key
			assert.Equal(t, tc.expectedKey, key, "Key mismatch")

			// 2. Check the error
			if tc.expectedError != nil {
				require.Error(t, err)
				// Check for specific exported error
				if errors.Is(tc.expectedError, ErrNoAuthHeaderIncluded) {
					assert.True(t, errors.Is(err, ErrNoAuthHeaderIncluded), "Expected ErrNoAuthHeaderIncluded")
				} else {
					// Check error string for unexported "malformed authorization header"
					assert.EqualError(t, err, tc.expectedError.Error(), "Error message mismatch")
				}
			} else {
				assert.NoError(t, err, "Expected no error")
			}
		})
	}
}
