/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joesiltberg/bowness/fedtls"
	"github.com/joesiltberg/bowness/server"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

func must(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func verifyRequired(keys ...string) {
	for _, key := range keys {
		if !viper.IsSet(key) {
			log.Fatalf("Missing required configuration setting: %s", key)
		}
	}
}

func stripHeader(h http.Handler, header string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := *r
		r2.Header = r.Header.Clone()
		r2.Header.Del(header)
		h.ServeHTTP(w, &r2)
	})
}

func newReverseProxy(target *url.URL) http.Handler {
	return stripHeader(httputil.NewSingleHostReverseProxy(target), "X-Forwarded-For")
}

func configuredSeconds(setting string) time.Duration {
	return time.Duration(viper.GetInt(setting)) * time.Second
}

func waitForShutdownSignal() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	<-signals
}

// This is meant to be set at build time with -ldflags,
// for instance with "git describe" or a hard coded version number.
var version = "version not set at build time"

func main() {
	viper.SetDefault("MetadataURL", "https://md.swefed.se/kontosynk/kontosynk-prod-1.jws")
	viper.SetDefault("DefaultCacheTTL", 3600)
	viper.SetDefault("NetworkRetry", 60)
	viper.SetDefault("BadContentRetry", 3600)
	viper.SetDefault("ReadHeaderTimeout", 5)
	viper.SetDefault("ReadTimeout", 20)
	viper.SetDefault("WriteTimeout", 40)
	viper.SetDefault("IdleTimeout", 60)
	viper.SetDefault("BackendTimeout", 30)
	viper.SetDefault("EnableLimiting", false)
	viper.SetDefault("LimitRequestsPerSecond", 10.0)
	viper.SetDefault("LimitBurst", 50)

	var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "display program version and exit")
	flag.BoolVar(&versionFlag, "v", false, "alias for version")

	var helpFlag bool
	flag.BoolVar(&helpFlag, "help", false, "display command line usage and exit")
	flag.BoolVar(&helpFlag, "h", false, "alias for help")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <config-file>\nWhere options can include:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if helpFlag {
		flag.Usage()
		return
	}

	if versionFlag {
		fmt.Fprintf(os.Stdout, "bowness reverse proxy (%s)\n", version)
		return
	}

	if flag.NArg() < 1 {
		flag.Usage()
		log.Fatal("Missing configuration file path")
	}

	configPath := flag.Arg(0)

	viper.SetConfigFile(configPath)

	must(viper.ReadInConfig())

	verifyRequired("JWKSPath", "CachePath", "Cert", "Key", "TargetURL", "ListenAddress")

	mdstore := fedtls.NewMetadataStore(
		viper.GetString("MetadataURL"),
		viper.GetString("JWKSPath"),
		viper.GetString("CachePath"),
		fedtls.DefaultCacheTTL(configuredSeconds("DefaultCacheTTL")),
		fedtls.NetworkRetry(configuredSeconds("NetworkRetry")),
		fedtls.BadContentRetry(configuredSeconds("BadContentRetry")))

	certFile := viper.GetString("Cert")
	keyFile := viper.GetString("Key")

	mdTLSConfigManager, err := server.NewMetadataTLSConfigManager(certFile, keyFile, mdstore)

	if err != nil {
		log.Fatalf("Failed to create TLS configuration: %v", err)
	}

	target, err := url.Parse(viper.GetString("TargetURL"))

	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	proxyHandler := newReverseProxy(target)

	enableLimiting := viper.GetBool("EnableLimiting")

	if enableLimiting {
		proxyHandler = server.Limiter(proxyHandler,
			rate.Limit(viper.GetFloat64("LimitRequestsPerSecond")),
			viper.GetInt("LimitBurst"))
	}

	beTimeout := configuredSeconds("BackendTimeout")
	if beTimeout >= 1*time.Second {
		proxyHandler = http.TimeoutHandler(proxyHandler, beTimeout, "Backend timeout")
	}

	srv := &http.Server{
		// Wrap the HTTP handler with authentication middleware.
		Handler: server.AuthMiddleware(proxyHandler, mdstore),

		// In order to use the authentication middleware, the server needs
		// to have a ConnContext configured so the middleware can access
		// connection specific information.
		ConnContext: server.ContextModifier(),

		ReadHeaderTimeout: configuredSeconds("ReadHeaderTimeout"),
		ReadTimeout:       configuredSeconds("ReadTimeout"),
		WriteTimeout:      configuredSeconds("WriteTimeout"),
		IdleTimeout:       configuredSeconds("IdleTimeout"),
	}

	// Set up a TLS listener with certificate authorities loaded from
	// federation metadata (and dynamically updated as metadata gets refreshed).
	address := viper.GetString("ListenAddress")
	listener, err := tls.Listen("tcp", address, mdTLSConfigManager.Config())

	if err != nil {
		log.Fatalf("Failed to listen to %s (%v)", address, err)
	}

	go func() {
		err := srv.Serve(listener)

		if err != http.ErrServerClosed {
			log.Fatalf("Unexpected server exit: %v", err)
		}
	}()

	waitForShutdownSignal()

	log.Printf("Shutting down, waiting for active requests to finish...")

	err = srv.Shutdown(context.Background())
	if err != nil {
		log.Printf("Failed to gracefully shutdown server: %v", err)
	}

	log.Printf("Server closed, waiting for metadata store to close...")
	mdstore.Quit()

	log.Printf("Done.")
}
