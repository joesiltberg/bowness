/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
)

// The TLSConfigManager constructs a dynamic tls.Config object used by TLS listeners.
//
// tls.Config supports hot-swapping CA stores etc without closing the listener.
// This type simplifies creating such a tls.Config for our purposes
// (We need to be able to replace the client certificate authorities when new metadata is loaded)
type TLSConfigManager struct {
	defaultConfig *tls.Config
	currentConfig *tls.Config

	// Our server cert, not currently hot-swappable
	certs []tls.Certificate

	lock sync.Mutex
}

// Returns a tls.Config with some basic settings we want to have
// both when we're creating the default and the current config.
func baseTLSConfig(certs []tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:             certs,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

func NewTLSConfigManager(certFile, keyFile string) (*TLSConfigManager, error) {
	mgr := &TLSConfigManager{}

	var err error
	mgr.certs = make([]tls.Certificate, 1)
	mgr.certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)

	if err != nil {
		return nil, err
	}

	getCurrentConfig := func(*tls.ClientHelloInfo) (*tls.Config, error) {
		mgr.lock.Lock()
		defer mgr.lock.Unlock()

		return mgr.currentConfig, nil
	}

	// The default config is only used until valid metadata has been loaded,
	// it will deny any incoming connections since it requires verified
	// client certs but none are installed.
	config := baseTLSConfig(mgr.certs)
	config.GetConfigForClient = getCurrentConfig

	mgr.defaultConfig = config
	mgr.currentConfig = nil

	return mgr, nil
}

// Config will return a tls.Config that can be used by a TLS listener
func (mgr *TLSConfigManager) Config() *tls.Config {
	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	return mgr.defaultConfig
}

// SetTrusted replaces the client certificate authorities
func (mgr *TLSConfigManager) SetTrusted(clientCAs *x509.CertPool) {
	newConfig := baseTLSConfig(mgr.certs)
	newConfig.ClientCAs = clientCAs

	mgr.lock.Lock()
	defer mgr.lock.Unlock()

	mgr.currentConfig = newConfig
}
