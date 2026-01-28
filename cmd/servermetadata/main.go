/*
 * Copyright (c) 2020-2026 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joesiltberg/bowness/fedtls"
	"github.com/joesiltberg/bowness/util"
)

type stringSlice []string

func (s *stringSlice) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func readCertificate(path string) (string, *x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	derData, _ := pem.Decode(pemData)
	if derData == nil {
		return "", nil, fmt.Errorf("failed to decode PEM data from %s", path)
	}

	cert, err := x509.ParseCertificate(derData.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate from %s: %w", path, err)
	}

	return string(pemData), cert, nil
}

func main() {
	var (
		organization   string
		organizationID string
		entityID       string
		baseURI        string
		certPath       string
		description    string
		issuerPaths    stringSlice
		tags           stringSlice
	)

	flag.StringVar(&organization, "organization", "", "Organization name (required)")
	flag.StringVar(&organizationID, "organization-id", "", "Organization ID (required)")
	flag.StringVar(&entityID, "entity-id", "", "Entity ID (required)")
	flag.StringVar(&baseURI, "base-uri", "", "Base URI (required)")
	flag.StringVar(&certPath, "cert", "", "Path to server certificate in PEM format (required)")
	flag.StringVar(&description, "description", "", "Server description (optional)")
	flag.Var(&issuerPaths, "issuer", "Path to issuer certificate in PEM format (optional, can be specified multiple times)")
	flag.Var(&tags, "tag", "Tag for the server (optional, can be specified multiple times)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nGenerates FedTLS metadata for a server.\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate required parameters
	missing := []string{}
	if organization == "" {
		missing = append(missing, "-organization")
	}
	if organizationID == "" {
		missing = append(missing, "-organization-id")
	}
	if entityID == "" {
		missing = append(missing, "-entity-id")
	}
	if baseURI == "" {
		missing = append(missing, "-base-uri")
	}
	if certPath == "" {
		missing = append(missing, "-cert")
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "Error: missing required parameters: %v\n\n", missing)
		flag.Usage()
		os.Exit(1)
	}

	// Read server certificate and compute pin
	_, cert, err := readCertificate(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pin := fedtls.Pin{
		Alg:    "sha256",
		Digest: util.Fingerprint(cert),
	}

	// Build issuers list from issuer certificates
	issuers := []fedtls.Issuer{}
	for _, issuerPath := range issuerPaths {
		issuerPEM, _, err := readCertificate(issuerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		issuers = append(issuers, fedtls.Issuer{X509certificate: issuerPEM})
	}

	// Build server
	server := fedtls.Server{
		BaseURI: baseURI,
		Tags:    tags,
		Pins:    []fedtls.Pin{pin},
	}

	if description != "" {
		server.Description = &description
	}

	// Build entity
	entity := fedtls.Entity{
		Issuers:        issuers,
		Servers:        []fedtls.Server{server},
		EntityID:       entityID,
		Organization:   &organization,
		OrganizationID: &organizationID,
	}

	// Build metadata
	metadata := fedtls.Metadata{
		Version:  "1.0.0",
		Entities: []fedtls.Entity{entity},
	}

	// Output as JSON
	output, err := json.MarshalIndent(&metadata, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to marshal metadata: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
