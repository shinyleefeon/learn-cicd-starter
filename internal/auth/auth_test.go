package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "returns api key for valid header",
			authHeader:  "ApiKey abc123",
			expectedKey: "abc123",
		},
		{
			name:        "returns sentinel error when header missing",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "returns error for wrong scheme",
			authHeader:  "Bearer abc123",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "returns error for missing api key value",
			authHeader:  "ApiKey",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authHeader != "" {
				headers.Set("Authorization", tc.authHeader)
			}

			apiKey, err := GetAPIKey(headers)

			if tc.expectedErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.expectedErr.Error())
				}
				if err.Error() != tc.expectedErr.Error() {
					t.Fatalf("expected error %q, got %q", tc.expectedErr.Error(), err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if apiKey != tc.expectedKey {
				t.Fatalf("expected api key %q, got %q", tc.expectedKey, apiKey)
			}
		})
	}
}
