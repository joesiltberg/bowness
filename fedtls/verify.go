/*
 * Copyright (c) 2020-2026 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package fedtls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// VerifyOption is an option for the Verify and VerifyRaw functions.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	inferAlgorithm bool
}

// WithInferAlgorithm enables algorithm inference from the key type when the key
// is missing the alg property.
func WithInferAlgorithm(v bool) VerifyOption {
	return func(o *verifyOptions) {
		o.inferAlgorithm = v
	}
}

// VerifyRaw verifies the signed metadata using the provided JWKS.
// It returns the raw payload if the verification is successful.
// See Verify for a version that also unmarshals the payload into a Metadata struct.
func VerifyRaw(signed, jwks []byte, opts ...VerifyOption) ([]byte, error) {
	var options verifyOptions
	for _, opt := range opts {
		opt(&options)
	}

	keyset, err := jwk.Parse(jwks)

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	r := bytes.NewReader(signed)
	message, err := jws.ParseReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %v", err)
	}

	payload, err := jws.Verify(signed, jws.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(options.inferAlgorithm)))

	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %v", err)
	}

	if expstr, ok := message.Signatures()[0].ProtectedHeaders().Get("exp"); ok {
		exp := time.Unix(int64(expstr.(float64)), 0)

		if time.Now().After(exp) {
			return nil, fmt.Errorf("metadata expired at %v, current time: %v", exp, time.Now())
		}
	}

	return payload, nil
}

// Verify verifies the signed metadata using the provided JWKS.
// It returns the parsed Metadata if the verification is successful.
func Verify(signed, jwks []byte, opts ...VerifyOption) (*Metadata, error) {
	payload, err := VerifyRaw(signed, jwks, opts...)
	if err != nil {
		return nil, err
	}

	var result Metadata

	err = json.Unmarshal(payload, &result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}
