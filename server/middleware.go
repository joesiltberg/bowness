/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"context"
	"net/http"

	"github.com/joesiltberg/bowness/fedtls"
)

type entityContextKey int

const (
	entityIDKey entityContextKey = iota
	organizationKey
	organizationIDKey
)

const (
	entityIDHeader       string = "X-FedTLSAuth-Entity-ID"
	organizationHeader          = "X-FedTLSAuth-Organization"
	organizationIDHeader        = "X-FedTLSAuth-Organization-ID"
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
func setOrClear(h http.Header, headerName string, value *string) {
	if value != nil {
		h.Set(headerName, *value)
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

// AuthMiddleware is the authentication middlware for federated TLS authentication.
//
// It assumes that the http.Server is set up with a ConnContext as provided
// by ContextModifier() so that the middleware can access the connection of
// the request and store some authentication state in the context associated
// with the connection.
func AuthMiddleware(h http.Handler, mdstore *fedtls.MetadataStore, apiKey *APIKey) http.Handler {

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

		r2.Header.Set(entityIDHeader, entityID)
		setOrClear(r2.Header, organizationHeader, org)
		setOrClear(r2.Header, organizationIDHeader, orgID)

		if apiKey != nil {
			r2.Header.Set(apiKey.HeaderName, apiKey.Key)
		}

		h.ServeHTTP(w, r2)
	})
}
