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
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/appvia/anchore-rbac/internal/utils"
	"github.com/appvia/anchore-rbac/models"
)

type authzService struct {
	sync.RWMutex

	principals map[string][]string
}

// New creates and returns a new authorization service
func New(accounts *Accounts) (Interface, error) {
	svc := &authzService{}
	if err := svc.UpdatePermissions(accounts); err != nil {
		return nil, err
	}

	return svc, nil
}

// NewFromReloadable creates and returns a authorization service
func NewFromReloadable(filename string) (Interface, error) {
	svc := &authzService{}
	accounts := &Accounts{}

	// @step: read in the account for the first time
	watcher := utils.NewWatcher(filename)
	if err := watcher.Read(accounts); err != nil {
		return nil, err
	}

	if err := svc.UpdatePermissions(accounts); err != nil {
		return nil, err
	}

	if _, err := watcher.Watch(&utils.WatcherHandlerFuncs{
		ErrorFunc: func(err error) {
			log.WithFields(log.Fields{"error": err.Error()}).Error("recieved an error from the watcher")
		},
		UpdatedFunc: func() {
			// @step: attempt to read in the configuration and set it
			if err := func() error {
				nc := &Accounts{}

				log.Info("received an update from watcher the configuration has changed")

				if err := watcher.Read(nc); err != nil {
					return err
				}
				if err := svc.UpdatePermissions(nc); err != nil {
					return err
				}

				log.Info("successfully updated the configuration")

				return nil
			}(); err != nil {

				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Error("failed to read on the updated configuration")

				return
			}
		},
	}); err != nil {
		return nil, err
	}

	return svc, nil
}

// Authorize is responsible for validating the incoming request
func (a *authzService) Authorize(request *models.AuthorizationRequest) (*models.AuthorizationDecision, error) {
	defaultTTL := int64(60)

	decision := &models.AuthorizationDecision{
		Principal: request.Principal,
		Allowed:   models.ActionSet{},
		Denied:    models.ActionSet{},
		TTL:       &defaultTTL,
	}

	// @check the request contains a principal
	principal := strings.ToLower(sv(request.Principal.Name))
	if principal == "" {
		log.Error("request does not contain a principal, unable to continue")
		decision.Denied = request.Actions

		return decision, nil
	}

	err := func() error {
		// @step: build a action list of all actions the principal is allowed to perform (not we are not using
		// resource level permisions here)
		permitted, found := a.getPermissions(principal)
		if !found {
			decision.Denied = request.Actions
			return nil
		}

		// @step: iterate the actions requested against the principle
		for _, x := range request.Actions {
			found := func() bool {
				for _, j := range permitted {
					if strings.ToLower(sv(x.Action)) == strings.ToLower(j) {
						return true
					}
				}

				return false
			}()

			if !found {
				decision.Denied = append(decision.Denied, x)
			} else {
				decision.Allowed = append(decision.Allowed, x)
			}
		}

		return nil
	}()
	if err != nil {
		log.WithFields(log.Fields{
			"error":     err.Error(),
			"principal": principal,
		}).Error("failed to authorize request due to internal error")
	}

	// @step: print a logging message for request which has been denied
	if len(decision.Denied) > 0 {
		fields := log.Fields{
			"principal": principal,
		}
		for i, x := range decision.Denied {
			fields[fmt.Sprintf("action.%d", i)] = sv(x.Action)
		}
		log.WithFields(fields).Warn("principal has been denied")
	}

	return decision, nil
}

// AddDomain is called when adding a domain
func (a *authzService) AddDomain(domain *models.Domain) error {
	log.WithFields(log.Fields{
		"name": domain.Name,
	}).Info("a domain has been added via the api")

	return nil
}

// DeleteDomain is called when deleting a domain
func (a *authzService) DeleteDomain(domain *models.Domain) error {
	log.WithFields(log.Fields{
		"name": domain.Name,
	}).Info("a domain has been delete via the api")

	return nil
}

// Domains is called to list all the domains
func (a *authzService) Domains() (models.DomainList, error) {
	var list models.DomainList

	for _, x := range a.getPrincipals() {
		list = append(list, &models.Domain{Name: s(x)})
	}

	return list, nil
}

// Principals is called to list all the principals
func (a *authzService) Principals() (models.PrincipalList, error) {
	var list models.PrincipalList

	for _, x := range a.getPrincipals() {
		list = append(list, &models.Principal{Name: s(x)})
	}

	return list, nil
}

// AddPrincipal is called to add a principle
func (a *authzService) AddPrincipal(principal *models.Principal) error {
	log.WithFields(log.Fields{
		"name": principal.Name,
	}).Info("a principal has been added via the api")

	return nil
}

// DeletePrincipal is called to delete a principal
func (a *authzService) DeletePrincipal(principal *models.Principal) error {
	log.WithFields(log.Fields{
		"name": principal.Name,
	}).Info("a principal has been delete via the api")

	return nil
}

// Health return an error if the service is unhealthy
func (a *authzService) Health() error {
	return nil
}

// UpdatePermissions attempts to update the service permissions
func (a *authzService) UpdatePermissions(accounts *Accounts) error {
	// @check the account are ok
	if err := validateAccounts(accounts); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("failed to update permissions, accounts are invalid")

		return err
	}

	// @step: build a map of roles
	roles := make(map[string]*Role, 0)
	for _, x := range accounts.Roles {
		roles[x.Name] = x
	}

	principals := make(map[string][]string, 0)

	// @step: build a cache of principals and their permissions
	for _, x := range accounts.Principals {
		var list []string
		for _, j := range x.Roles {
			list = append(list, roles[j].Actions...)
		}
		principals[x.Name] = list
	}

	a.Lock()
	defer a.Unlock()

	a.principals = principals

	return nil
}

// getPrincipals returns a list of principals
func (a *authzService) getPrincipals() []string {
	a.RLock()
	defer a.RUnlock()

	var list []string
	for name := range a.principals {
		list = append(list, name)
	}

	return list
}

// getPermissions returns the permissions for the principal
func (a *authzService) getPermissions(principal string) ([]string, bool) {
	a.RLock()
	defer a.RUnlock()

	perms, found := a.principals[principal]
	if !found {
		return []string{}, false
	}

	return perms, true
}

func s(v string) *string {
	return &v
}

func sv(v *string) string {
	if v == nil {
		return ""
	}

	return *v
}
