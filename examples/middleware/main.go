/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/joesiltberg/bowness/fedtls"
	"github.com/joesiltberg/bowness/server"
)

// An HTTP handler that illustrates how to get information about the
// authenticated peer from the request context
func myHandler(w http.ResponseWriter, r *http.Request) {
	entityID := server.EntityIDFromContext(r.Context())
	org := server.OrganizationFromContext(r.Context())
	orgID := server.OrganizationIDFromContext(r.Context())

	fmt.Fprintf(w, "Hello world %s!\n", entityID)

	if org != nil {
		fmt.Fprintf(w, "Organization: %s\n", *org)
	}

	if orgID != nil {
		fmt.Fprintf(w, "OrganizationID: %s\n", *orgID)
	}
}

func main() {
	mdstore := fedtls.NewMetadataStore(
		//"https://md.swefed.se/kontosynk/kontosynk-prod-1.jws",
		//"jwks",
		"https://fedscim-poc.skolfederation.se/md/skolfederation-fedscim-0_1.json",
		"jwks.poc",
		"metadata-cache.json",
		fedtls.DefaultCacheTTL(2*time.Hour),
		fedtls.NetworkRetry(1*time.Minute),
		fedtls.BadContentRetry(1*time.Hour))

	certFile := "cert.pem"
	keyFile := "key.pem"

	mdTLSConfigManager, err := server.NewMetadataTLSConfigManager(certFile, keyFile, mdstore)

	if err != nil {
		log.Fatalf("Failed to create TLS configuration: %v", err)
	}

	srv := &http.Server{
		// Wrap the HTTP handler with authentication middleware.
		Handler: server.AuthMiddleware(http.HandlerFunc(myHandler), mdstore),

		// In order to use the authentication middleware, the server needs
		// to have a ConnContext configured so the middleware can access
		// connection specific information.
		ConnContext: server.ContextModifier(),
	}

	// Set up a TLS listener with certificate authorities loaded from
	// federation metadata (and dynamically updated as metadata gets refreshed).
	address := ":8443"
	listener, err := tls.Listen("tcp", address, mdTLSConfigManager.Config())

	if err != nil {
		log.Fatalf("Failed to listen to %s (%v)", address, err)
	}

	srv.Serve(listener)

	mdstore.Quit()
}
