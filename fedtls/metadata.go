/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package fedtls

import (
	"encoding/json"
	"errors"
)

// Pin is a RFC 7469 pin directive (digest of a public key)
type Pin struct {
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
}

// UnmarshalJSON parses the JSON for a pin
// We have our own implementation to support the old format
// where the attributes were named "name" and "value",
// once there are no active federations left with that format
// we can remove this.
func (p *Pin) UnmarshalJSON(b []byte) error {
	m := make(map[string]string)
	err := json.Unmarshal(b, &m)

	if err != nil {
		return err
	}

	if alg, ok := m["alg"]; ok {
		p.Alg = alg
	} else if name, ok := m["name"]; ok {
		p.Alg = name
	} else {
		return errors.New("pin missing alg attribute")
	}

	if digest, ok := m["digest"]; ok {
		p.Digest = digest
	} else if value, ok := m["value"]; ok {
		p.Digest = value
	} else {
		return errors.New("pin missing digest attribute")
	}

	return nil
}

// Client includes the information the server needs about a connecting client
type Client struct {
	Description *string `json:"description"`
	Pins        []Pin   `json:"pins"`
}

// Issuer is a certificate issuer for an entity
type Issuer struct {
	X509certificate string `json:"x509certificate"`
}

// Entity represents one of the actors registered in the federation
type Entity struct {
	Issuers        []Issuer `json:"issuers"`
	Clients        []Client `json:"clients"`
	EntityID       string   `json:"entity_id"`
	Organization   *string  `json:"organization"`
	OrganizationID *string  `json:"organization_id"`
}

// Metadata is the complete representation of all entities in the federation
type Metadata struct {
	CacheTTL int      `json:"cache_ttl"`
	Entities []Entity `json:"entities"`
}
