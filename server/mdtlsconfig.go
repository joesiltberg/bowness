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
	"log"

	"github.com/joesiltberg/bowness/fedtls"
)

// The MetadataTLSConfigManager creates and manages a tls.Config which can
// be used to set up a TLS listener with a CA store which changes dynamically
// as a MetadataStore fetches new metadata from the federation operator.
type MetadataTLSConfigManager struct {
	tlsConfigManager *TLSConfigManager
}

func buildCertPool(issuers fedtls.IssuersPerEntity) *x509.CertPool {
	pool := x509.NewCertPool()

	for issuer, certs := range issuers {
		for _, cert := range certs {
			ok := pool.AppendCertsFromPEM([]byte(cert.X509certificate))

			if !ok {
				log.Printf("Failed to add any certificates for issuer %s", issuer)
			}
		}
	}
	return pool
}

func updateTrust(mdstore *fedtls.MetadataStore, tlsConfigManager *TLSConfigManager) {
	certPool := buildCertPool(mdstore.GetIssuerCertificates())
	tlsConfigManager.SetTrusted(certPool)
}

// NewMetadataTLSConfigManager creates a new TLS config manager connected to a MetadataStore.
// The config manager will listen to changes from the metadata store and hot-swap the CA store.
func NewMetadataTLSConfigManager(certFile, keyFile string, mdstore *fedtls.MetadataStore) (*MetadataTLSConfigManager, error) {
	tlsConfigManager, err := NewTLSConfigManager(certFile, keyFile)

	if err != nil {
		return nil, err
	}

	metadataChange := make(chan int)
	mdstore.AddChangeListener(metadataChange)
	updateTrust(mdstore, tlsConfigManager)

	go func() {
		for {
			<-metadataChange
			updateTrust(mdstore, tlsConfigManager)
			log.Println("New metadata loaded")
		}
	}()

	return &MetadataTLSConfigManager{
		tlsConfigManager: tlsConfigManager,
	}, nil
}

// Config returns a tls.Config which can be used by a TLS listener.
func (mdTLSConfigManager *MetadataTLSConfigManager) Config() *tls.Config {
	return mdTLSConfigManager.tlsConfigManager.Config()
}
