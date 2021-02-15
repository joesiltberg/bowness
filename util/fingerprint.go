/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// Fingerprint returns the SHA256 fingerprint of a certificate's Subject Public Key Info
func Fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}
