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

	"github.com/PuerkitoBio/purell"
	"github.com/joesiltberg/bowness/fedtls"
)

type entityContextKey int

const (
	entityIDKey entityContextKey = iota
	organizationKey
	organizationIDKey
)

const (
	entityIDHeader           string = "X-FedTLSAuth-Entity-ID"
	normalizedEntityIDHeader        = "X-FedTLSAuth-Normalized-Entity-ID"
	organizationHeader              = "X-FedTLSAuth-Organization"
	organizationIDHeader            = "X-FedTLSAuth-Organization-ID"
)

// EntityIDFromContext returns the authenticated entity ID
//
// This can be called by a request handler so find out who made
// the request, assuming that the authentication middleware
// is in place before the request handler.
func EntityIDFromContext(ctx context.Context) string {
	return ctx.Value(entityIDKey).(string)
}

func normalizeEntityID(entityID string) string {
	normalized, err := purell.NormalizeURLString(entityID, purell.FlagsSafe)
	if err != nil {
		// This shouldn't happen assuming the federation ensures all entity ids are
		// valid URIs
		return entityID
	} else {
		return normalized
	}
}

// NormalizedEntityIDFromContext returns the authenticated entity ID in normalized form.
//
// Normalized for is more appropriate for comparing entity ids or when an entity id is
// used as a key for lookup.
func NormalizedEntityIDFromContext(ctx context.Context) string {
	entityID := EntityIDFromContext(ctx)
	return normalizeEntityID(entityID)
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

// AuthMiddleware is the authentication middlware for federated TLS authentication.
//
// It assumes that the http.Server is set up with a ConnContext as provided
// by ContextModifier() so that the middleware can access the connection of
// the request and store some authentication state in the context associated
// with the connection.
func AuthMiddleware(h http.Handler, mdstore *fedtls.MetadataStore) http.Handler {

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
		r2.Header.Set(normalizedEntityIDHeader, normalizeEntityID(entityID))
		setOrClear(r2.Header, organizationHeader, org)
		setOrClear(r2.Header, organizationIDHeader, orgID)

		h.ServeHTTP(w, r2)
	})
}
