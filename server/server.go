/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"context"
	"crypto/tls"
	"net"
)

// AuthStatus shows us if a connection is authenticated and if so, who the peer is
type AuthStatus struct {
	// Granted tells us if the connection was successfully authenticated
	Granted bool

	// EntityID will be set to the connecting peer's entity ID if Granted == true
	EntityID string

	// Set if Granted == true and there was an organization attribute for the entity in metadata
	Organization *string

	// Set if Granted == true and there was an organization id attribute for the entity in metadata
	OrganizationID *string
}

// ContextConnection is stored in the context used for all requests for a server
type ContextConnection struct {
	// The connection for the current request
	conn *tls.Conn

	// The authentication status of the connection.
	// nil means it's the first request and we haven't checked yet,
	// the middleware should do the authentication and set auth
	// apropriately.
	auth *AuthStatus
}

type connContextKey int

const connKey connContextKey = 0

// ConnContext is used by net/http.Server to set up a connection specific context
type ConnContext func(ctx context.Context, c net.Conn) context.Context

// ContextModifier returns a function that will modify the context for requests on a server
//
// The context will contain a ContextConnection, which allows the middleware
// to do the authentication based on client cert if it hasn't been done, or check
// the result of this authentication if it was done in a previous request.
func ContextModifier() ConnContext {
	return func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey, &ContextConnection{conn: c.(*tls.Conn)})
	}

}

// ConnectionFromContext gets the ContextConnection from the context.
//
// Typically called from the authentication middleware to do the
// authentication and either deny the request or send it through
// to the actual request handler.
func ConnectionFromContext(ctx context.Context) *ContextConnection {
	return ctx.Value(connKey).(*ContextConnection)
}
