/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package fedtls

import (
	"encoding/json"
	"reflect"
	"testing"
)

const minimalEntity string = `{
	"entity_id": "example.com",
	"issuers": []
}`

const entityWithOrg string = `{
	"entity_id": "example.com",
	"issuers": [],
	"organization": "Example Organization Ltd.",
	"organization_id": "123456-7890"
}`

func must(err error, t *testing.T) {
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func shouldEqualString(got, want, context string, t *testing.T) {
	if got != want {
		t.Errorf("%s: got: %s, want: %s", context, got, want)
	}
}

func shouldBeNil(p interface{}, context string, t *testing.T) {
	if reflect.ValueOf(p).Type().Kind() != reflect.Ptr {
		t.Errorf("%s: didn't get a pointer", context)
		return
	}
	if !reflect.ValueOf(p).IsNil() {
		t.Errorf("%s: expected nil", context)
	}
}

func mustNotBeNil(p interface{}, context string, t *testing.T) {
	if reflect.ValueOf(p).Type().Kind() != reflect.Ptr {
		t.Fatalf("%s: didn't get a pointer", context)
	}

	if reflect.ValueOf(p).IsNil() {
		t.Fatalf("%s: got nil", context)
	}
}

func TestUnmarshalMinimalEntity(t *testing.T) {
	var e Entity
	must(json.Unmarshal([]byte(minimalEntity), &e), t)

	shouldEqualString(e.EntityID, "example.com", "entity_id", t)
	shouldBeNil(e.Organization, "organization", t)
}

func TestUnmarshalOrganization(t *testing.T) {
	var e Entity
	must(json.Unmarshal([]byte(entityWithOrg), &e), t)
	mustNotBeNil(e.Organization, "organization", t)
	mustNotBeNil(e.OrganizationID, "organization_id", t)
	shouldEqualString(*e.Organization, "Example Organization Ltd.", "organization", t)
	shouldEqualString(*e.OrganizationID, "123456-7890", "organization_id", t)
}
