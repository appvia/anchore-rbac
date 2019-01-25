/*
Copyright 2018 Rohith Jayawardene <gambol99@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorization

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appvia/anchore-rbac/models"
)

const fakeAccounts = `
principals:
	analyzer:
  	roles: [analyzer]
		domains: [default]
	reporter:
  	roles: [reporter]
    domains: [default]

roles:
	reporter:
		actions:
		- getEvent
		- getImage
		- getImageEvaluation
		- getPolicy
		- getRegistry
		- getService
		- getSubscription
		- listEvents
		- listFeeds
		- listImages
		- listPolicies
		- listRegistries
		- listServices
		- listSubscriptions
		targets: ['*']
	analyzer:
		actions:
		- createImage
		- getEvent
		- getImage
		- getImageEvaluation
		- getSubscription
		- listEvents
		- listImages
		- listSubscriptions
		targets: ['*']
`

func makeTestAccounts() *Permissions {
	return &Permissions{
		Roles: map[string]*Role{
			"analyzer": {
				Actions: []string{
					"createImage",
					"getEvent",
					"getImage",
					"getImageEvaluation",
					"getSubscription",
					"listEvents",
					"listImages",
					"listSubscriptions",
				},
				Targets: []string{"*"},
			},
			"reporter": {
				Actions: []string{
					"getEvent",
					"getImage",
					"getImageEvaluation",
					"getPolicy",
					"getRegistry",
					"getService",
					"getSubscription",
					"listEvents",
					"listFeeds",
					"listImages",
					"listPolicies",
					"listRegistries",
					"listServices",
					"listSubscriptions",
				},
				Targets: []string{"*"},
			},
		},
		Principals: map[string]*Principal{
			"analyzer": {
				Roles:   []string{"analyzer"},
				Domains: []string{"default"},
			},
			"reports": {
				Roles:   []string{"reporter"},
				Domains: []string{"default"},
			},
			"combined": {
				Roles:   []string{"reporter", "analyzer"},
				Domains: []string{"default"},
			},
			"acp": {
				Roles:   []string{"reporter", "analyzer"},
				Domains: []string{"something"},
			},
		},
	}
}

func TestNew(t *testing.T) {
	s, err := New(makeTestAccounts())
	assert.NotNil(t, s)
	assert.NoError(t, err)
}

func TestNewFromReloadable(t *testing.T) {
	file, err := ioutil.TempFile("", "anchore-rbac-test.XXXXXX")
	require.NoError(t, err)
	require.NotNil(t, file)
	defer os.Remove(file.Name())

	_, err = file.WriteString(fakeAccounts)
	require.NoError(t, err)

	s, err := NewFromReloadable(file.Name())
	require.NoError(t, err)
	require.NotNil(t, s)

	//sv := s.(*authzService)
}

func TestHealth(t *testing.T) {
	s, err := New(makeTestAccounts())
	require.NotNil(t, s)
	require.NoError(t, err)

	err = s.Health()
	assert.NoError(t, err)
}

func TestAuthorize(t *testing.T) {
	svc, err := New(makeTestAccounts())
	require.NotNil(t, svc)
	require.NoError(t, err)

	defaultTTL := int64(60)

	cases := []struct {
		Request  *models.AuthorizationRequest
		Expected *models.AuthorizationDecision
	}{
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("no_there")},
				Actions:   models.ActionSet{},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("no_there")},
				Allowed:   models.ActionSet{},
				Denied:    models.ActionSet{},
				TTL:       &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("no_there")},
				Actions: models.ActionSet{
					{Action: s("listimages"), Domain: s("default"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("no_there")},
				Allowed:   models.ActionSet{},
				Denied: models.ActionSet{
					{Action: s("listimages"), Domain: s("default"), Target: s("*")},
				},
				TTL: &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("analyzer")},
				Actions: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("analyzer")},
				Allowed: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
				Denied: models.ActionSet{},
				TTL:    &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("analyzer")},
				Actions: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("analyzer")},
				Allowed: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
				Denied: models.ActionSet{},
				TTL:    &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("acp")},
				Actions: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("acp")},
				Allowed:   models.ActionSet{},
				Denied: models.ActionSet{
					{Action: s("getEvent"), Domain: s("default"), Target: s("*")},
				},
				TTL: &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("combined")},
				Actions: models.ActionSet{
					{Action: s("createImage"), Domain: s("default"), Target: s("*")},
					{Action: s("listRegistries"), Domain: s("default"), Target: s("*")},
					{Action: s("bad"), Domain: s("default"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("combined")},
				Allowed: models.ActionSet{
					{Action: s("createImage"), Domain: s("default"), Target: s("*")},
					{Action: s("listRegistries"), Domain: s("default"), Target: s("*")},
				},
				Denied: models.ActionSet{
					{Action: s("bad"), Domain: s("default"), Target: s("*")},
				},
				TTL: &defaultTTL,
			},
		},
	}
	for _, c := range cases {
		decision, err := svc.Authorize(c.Request)
		assert.NoError(t, err)
		if !assert.Equal(t, c.Expected, decision) {
			fmt.Printf("EXPECTED: %s\n", spew.Sdump(c.Expected))
			fmt.Printf("GOT: %s\n", spew.Sdump(decision))

		}
	}
}
