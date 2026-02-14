package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		authHeader string
		wantKey    string
		wantErr    error
	}{
		"valid header returns key": {
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
			wantErr:    nil,
		},
		"missing Authorization header returns ErrNoAuthHeaderIncluded": {
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		"wrong scheme returns malformed error": {
			authHeader: "Bearer abc123",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
		"missing key returns malformed error": {
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		tc := tc // capture range variable
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := make(http.Header)
			if tc.authHeader != "" {
				h.Set("Authorization", tc.authHeader)
			}

			gotKey, gotErr := GetAPIKey(h)

			// Check key
			if gotKey != tc.wantKey {
				t.Fatalf("key mismatch: got %q, want %q", gotKey, tc.wantKey)
			}

			// Check error
			switch {
			case tc.wantErr == nil && gotErr != nil:
				t.Fatalf("expected no error, got %v", gotErr)
			case tc.wantErr != nil && gotErr == nil:
				t.Fatalf("expected error %v, got nil", tc.wantErr)
			case tc.wantErr != nil:
				// For the sentinel error, use errors.Is
				if errors.Is(tc.wantErr, ErrNoAuthHeaderIncluded) {
					if !errors.Is(gotErr, ErrNoAuthHeaderIncluded) {
						t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", gotErr)
					}
				} else {
					// For other errors, compare message
					if gotErr.Error() != tc.wantErr.Error() {
						t.Fatalf("error mismatch: got %q, want %q", gotErr.Error(), tc.wantErr.Error())
					}
				}
			}
		})
	}
}
