package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     error
		expectError bool
	}{
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
			expectError: true,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
			expectError: true,
		},
		{
			name: "Malformed Authorization Header - Missing Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
			expectError: true,
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey:     "abc123",
			wantErr:     nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got error: %v", tt.expectError, err)
				return
			}
			if tt.expectError && err.Error() != tt.wantErr.Error() {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			}
			if gotKey != tt.wantKey {
				t.Errorf("expected key: %s, got: %s", tt.wantKey, gotKey)
			}
		})
	}
}
