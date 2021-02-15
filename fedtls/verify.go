/*
 * Copyright (c) 2020-2021 Joe Siltberg
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

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func verify(signed, jwks []byte) (*Metadata, error) {
	keyset, err := jwk.ParseBytes(jwks)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWKS: %v", err)
	}

	r := bytes.NewReader(signed)
	message, err := jws.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWS: %v", err)
	}

	payload, err := jws.VerifyWithJWKSet(signed, keyset, nil)

	if err != nil {
		return nil, fmt.Errorf("Failed to verify JWS: %v", err)
	}

	if expstr, ok := message.Signatures()[0].ProtectedHeaders().Get("exp"); ok {
		exp := time.Unix(int64(expstr.(float64)), 0)

		if time.Now().After(exp) {
			return nil, fmt.Errorf("Metadata expired at %v, current time: %v", exp, time.Now())
		}
	}

	var result Metadata

	err = json.Unmarshal(payload, &result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}
