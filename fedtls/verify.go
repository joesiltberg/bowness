/*
 * Copyright (c) 2020-2025 Joe Siltberg
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

func verify(signed, jwks []byte) (*Metadata, error) {
	keyset, err := jwk.Parse(jwks)

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	r := bytes.NewReader(signed)
	message, err := jws.ParseReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %v", err)
	}

	payload, err := jws.Verify(signed, jws.WithKeySet(keyset))

	if err != nil {
		return nil, fmt.Errorf("failed to verify JWS: %v", err)
	}

	if expstr, ok := message.Signatures()[0].ProtectedHeaders().Get("exp"); ok {
		exp := time.Unix(int64(expstr.(float64)), 0)

		if time.Now().After(exp) {
			return nil, fmt.Errorf("metadata expired at %v, current time: %v", exp, time.Now())
		}
	}

	var result Metadata

	err = json.Unmarshal(payload, &result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}
