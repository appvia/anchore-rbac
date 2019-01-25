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

	"github.com/appvia/anchore-rbac/models"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeAccounts = `
principals:
- name: analyzer
  roles: [analyzer]
- name: reporter
  roles: [reporter]
roles:
- name: reporter
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
- name: analyzer
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

func makeTestAccounts() *Accounts {
	return &Accounts{
		Roles: []*Role{
			{
				Name: "analyzer",
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
			{
				Name: "reporter",
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
		Principals: []*Principal{
			{
				Name:  "analyzer",
				Roles: []string{"analyzer"},
			},
			{
				Name:  "reports",
				Roles: []string{"reporter"},
			},
			{
				Name:  "combined",
				Roles: []string{"reporter", "analyzer"},
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

	sv := s.(*authzService)
	fmt.Printf("%s\n", spew.Sdump(sv.principals))
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
					{Action: s("listimages"), Domain: s("images"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("no_there")},
				Allowed:   models.ActionSet{},
				Denied: models.ActionSet{
					{Action: s("listimages"), Domain: s("images"), Target: s("*")},
				},
				TTL: &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("analyzer")},
				Actions: models.ActionSet{
					{Action: s("getEvent"), Domain: s("images"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("analyzer")},
				Allowed: models.ActionSet{
					{Action: s("getEvent"), Domain: s("images"), Target: s("*")},
				},
				Denied: models.ActionSet{},
				TTL:    &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("analyzer")},
				Actions: models.ActionSet{
					{Action: s("getevent"), Domain: s("images"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("analyzer")},
				Allowed: models.ActionSet{
					{Action: s("getevent"), Domain: s("images"), Target: s("*")},
				},
				Denied: models.ActionSet{},
				TTL:    &defaultTTL,
			},
		},
		{
			Request: &models.AuthorizationRequest{
				Principal: &models.Principal{Name: s("combined")},
				Actions: models.ActionSet{
					{Action: s("createImage"), Domain: s("images"), Target: s("*")},
					{Action: s("listRegistries"), Domain: s("images"), Target: s("*")},
					{Action: s("bad"), Domain: s("images"), Target: s("*")},
				},
			},
			Expected: &models.AuthorizationDecision{
				Principal: &models.Principal{Name: s("combined")},
				Allowed: models.ActionSet{
					{Action: s("createImage"), Domain: s("images"), Target: s("*")},
					{Action: s("listRegistries"), Domain: s("images"), Target: s("*")},
				},
				Denied: models.ActionSet{
					{Action: s("bad"), Domain: s("images"), Target: s("*")},
				},
				TTL: &defaultTTL,
			},
		},
	}
	for _, c := range cases {
		decision, err := svc.Authorize(c.Request)
		assert.NoError(t, err)
		assert.Equal(t, c.Expected, decision)
	}
}
