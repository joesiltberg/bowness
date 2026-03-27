/*
 * Copyright (c) 2020-2025 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/joesiltberg/bowness/fedtls"
)

// HeaderEncoding represents how a header value should be encoded.
type HeaderEncoding int

const (
	// NoEncoding sends the header value as-is (default behaviour).
	NoEncoding HeaderEncoding = iota
	// URLEncoding percent-encodes the header value (compatible with url.QueryEscape).
	URLEncoding
	// Base64Encoding encodes the header value with standard base64 encoding.
	Base64Encoding
)

// ParseHeaderEncoding parses a case-insensitive encoding name.
// Accepted values are "" (no encoding), "url", and "base64".
func ParseHeaderEncoding(s string) (HeaderEncoding, error) {
	switch strings.ToLower(s) {
	case "":
		return NoEncoding, nil
	case "url":
		return URLEncoding, nil
	case "base64":
		return Base64Encoding, nil
	default:
		return NoEncoding, fmt.Errorf("unknown header encoding %q, accepted values are \"url\" and \"base64\" (leave unset for no encoding)", s)
	}
}

// encodeHeaderValue applies the given encoding to value.
func encodeHeaderValue(value string, encoding HeaderEncoding) string {
	switch encoding {
	case URLEncoding:
		return url.QueryEscape(value)
	case Base64Encoding:
		return base64.StdEncoding.EncodeToString([]byte(value))
	default:
		return value
	}
}

// HeaderEncodings configures the encoding used for each federated TLS auth header.
// A zero value uses NoEncoding for every header.
type HeaderEncodings struct {
	EntityID       HeaderEncoding
	Organization   HeaderEncoding
	OrganizationID HeaderEncoding
}

type entityContextKey int

const (
	entityIDKey entityContextKey = iota
	organizationKey
	organizationIDKey
)

const (
	entityIDHeader       string = "X-FedTLSAuth-Entity-ID"
	organizationHeader   string = "X-FedTLSAuth-Organization"
	organizationIDHeader string = "X-FedTLSAuth-Organization-ID"
)

// EntityIDFromContext returns the authenticated entity ID
//
// This can be called by a request handler so find out who made
// the request, assuming that the authentication middleware
// is in place before the request handler.
func EntityIDFromContext(ctx context.Context) string {
	return ctx.Value(entityIDKey).(string)
}

// OrganizationFromContext returns the peer's organization or nil
//
// nil is returned if the organization property isn't set for the entity in the
// metadata.
func OrganizationFromContext(ctx context.Context) *string {
	return ctx.Value(organizationKey).(*string)
}

// OrganizationIDFromContext returns the peer's organization ID or nil
//
// nil is returned if the organization_id property isn't set for the entity in the
// metadata.
func OrganizationIDFromContext(ctx context.Context) *string {
	return ctx.Value(organizationIDKey).(*string)
}

// Sets or clears an HTTP header depending on whether the value sent
// in is nil or not.
func setOrClear(h http.Header, headerName string, value *string, encoding HeaderEncoding) {
	if value != nil {
		h.Set(headerName, encodeHeaderValue(*value, encoding))
	} else {
		h.Del(headerName)
	}
}

// APIKey is used to configure an API key to use in all requests
// made by the middleware.
type APIKey struct {
	HeaderName string // Name of HTTP header to use
	Key        string // The actual API key
}

// AuthMiddlewareOption is a functional option for configuring AuthMiddleware.
type AuthMiddlewareOption func(*authMiddlewareConfig)

type authMiddlewareConfig struct {
	encodings HeaderEncodings
}

// WithHeaderEncodings returns an AuthMiddlewareOption that configures the
// encoding used for the X-FedTLSAuth headers forwarded to the backend.
func WithHeaderEncodings(enc HeaderEncodings) AuthMiddlewareOption {
	return func(cfg *authMiddlewareConfig) {
		cfg.encodings = enc
	}
}

// AuthMiddleware is the authentication middlware for federated TLS authentication.
//
// It assumes that the http.Server is set up with a ConnContext as provided
// by ContextModifier() so that the middleware can access the connection of
// the request and store some authentication state in the context associated
// with the connection.
//
// Optional configuration can be provided using AuthMiddlewareOption values,
// for example WithHeaderEncodings.
func AuthMiddleware(h http.Handler, mdstore *fedtls.MetadataStore, apiKey *APIKey, opts ...AuthMiddlewareOption) http.Handler {
	cfg := &authMiddlewareConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	enc := cfg.encodings

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		connection := ConnectionFromContext(ctx)
		errorString := "Unauthorized"

		if connection.auth == nil {
			entityID, org, orgID, err := mdstore.LookupClient(connection.conn.ConnectionState().VerifiedChains)

			connection.auth = &AuthStatus{
				Granted:        err == nil,
				EntityID:       entityID,
				Organization:   org,
				OrganizationID: orgID,
			}

			if err != nil {
				errorString = err.Error()
			}
		}

		if !connection.auth.Granted {
			http.Error(w, errorString, http.StatusForbidden)
			return
		}

		entityID := connection.auth.EntityID
		org := connection.auth.Organization
		orgID := connection.auth.OrganizationID

		newContext := context.WithValue(ctx, entityIDKey, entityID)
		newContext = context.WithValue(newContext, organizationKey, org)
		newContext = context.WithValue(newContext, organizationIDKey, orgID)
		r2 := r.Clone(newContext)

		r2.Header.Set(entityIDHeader, encodeHeaderValue(entityID, enc.EntityID))
		setOrClear(r2.Header, organizationHeader, org, enc.Organization)
		setOrClear(r2.Header, organizationIDHeader, orgID, enc.OrganizationID)

		if apiKey != nil {
			r2.Header.Set(apiKey.HeaderName, apiKey.Key)
		}

		h.ServeHTTP(w, r2)
	})
}
