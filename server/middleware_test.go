/*
 * Copyright (c) 2020-2026 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"testing"
)

func TestParseHeaderEncoding(t *testing.T) {
	tests := []struct {
		input   string
		want    HeaderEncoding
		wantErr bool
	}{
		{"", NoEncoding, false},
		{"url", URLEncoding, false},
		{"URL", URLEncoding, false},
		{"Url", URLEncoding, false},
		{"base64", Base64Encoding, false},
		{"BASE64", Base64Encoding, false},
		{"Base64", Base64Encoding, false},
		{"invalid", NoEncoding, true},
		{"gzip", NoEncoding, true},
	}

	for _, tc := range tests {
		got, err := ParseHeaderEncoding(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseHeaderEncoding(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseHeaderEncoding(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseHeaderEncoding(%q): got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestEncodeHeaderValue(t *testing.T) {
	tests := []struct {
		input    string
		encoding HeaderEncoding
		want     string
	}{
		// NoEncoding passes through unchanged
		{"example.com", NoEncoding, "example.com"},
		{"Örganisation AB", NoEncoding, "Örganisation AB"},

		// URL encoding
		{"example.com", URLEncoding, "example.com"},
		{"Örganisation AB", URLEncoding, "%C3%96rganisation+AB"},
		{"spaces here", URLEncoding, "spaces+here"},

		// Base64 encoding
		{"example.com", Base64Encoding, "ZXhhbXBsZS5jb20="},
		{"Örganisation AB", Base64Encoding, "w5ZyZ2FuaXNhdGlvbiBBQg=="},
	}

	for _, tc := range tests {
		got := encodeHeaderValue(tc.input, tc.encoding)
		if got != tc.want {
			t.Errorf("encodeHeaderValue(%q, %v): got %q, want %q", tc.input, tc.encoding, got, tc.want)
		}
	}
}
