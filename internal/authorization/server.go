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
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/appvia/anchore-rbac/internal/utils"
	"github.com/appvia/anchore-rbac/models"
)

type authzService struct {
	sync.RWMutex
	// the permission for the principals
	permissions *Permissions
}

// New creates and returns a new authorization service
func New(permissions *Permissions) (Interface, error) {
	svc := &authzService{}
	if err := svc.UpdatePermissions(permissions); err != nil {
		return nil, err
	}

	return svc, nil
}

// NewFromReloadable creates and returns a authorization service
func NewFromReloadable(filename string) (Interface, error) {
	svc := &authzService{}
	permissions := &Permissions{}

	// @step: read in the account for the first time
	watcher := utils.NewWatcher(filename)
	if err := watcher.Read(permissions); err != nil {
		return nil, err
	}

	if err := svc.UpdatePermissions(permissions); err != nil {
		return nil, err
	}

	if _, err := watcher.Watch(&utils.WatcherHandlerFuncs{
		ErrorFunc: func(err error) {
			log.WithFields(log.Fields{"error": err.Error()}).Error("recieved an error from the watcher")
		},
		UpdatedFunc: func() {
			// @step: attempt to read in the configuration and set it
			if err := func() error {
				nc := &Permissions{}

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
	principal := sv(request.Principal.Name)
	if principal == "" {
		log.Error("request does not contain a principal, unable to continue")
		decision.Denied = request.Actions

		return decision, nil
	}

	err := func() error {
		permissions := a.getPermissions()

		// @check the principal exists
		acl, found := permissions.Principals[principal]
		if !found {
			decision.Denied = request.Actions

			return nil
		}

		for _, action := range request.Actions {
			permitted := func() bool {
				domain := sv(action.Domain)
				operation := sv(action.Action)
				target := sv(action.Target)

				// @step: we check if the principal is permitted to act in the domain
				if !contains(domain, append([]string{"*"}, acl.Domains...)) {
					return false
				}

				matched := func() bool {
					// @step: we iterate the role of the principle
					for _, name := range acl.Roles {
						role, found := permissions.Roles[name]
						if !found {
							continue
						}

						// @step: we check the role has the require action
						if !contains(operation, append([]string{"*"}, role.Actions...)) {
							continue
						}

						// @step: so the role has the action, now lets check it has the target
						if contains(target, append([]string{"*"}, role.Targets...)) {
							return true
						}
					}

					// @step: we've iterating all the roles and nothing has it
					return false
				}()

				return matched
			}()

			switch permitted {
			case true:
				decision.Allowed = append(decision.Allowed, action)
			default:
				decision.Denied = append(decision.Denied, action)
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
	var list []string

	for _, principal := range a.getPermissions().Principals {
		for _, x := range principal.Domains {
			if !contains(x, list) {
				list = append(list, x)
			}
		}
	}

	var domains models.DomainList

	for _, x := range list {
		domains = append(domains, &models.Domain{Name: s(x)})
	}

	return domains, nil
}

// Principals is called to list all the principals
func (a *authzService) Principals() (models.PrincipalList, error) {
	var list models.PrincipalList

	for name := range a.getPermissions().Principals {
		list = append(list, &models.Principal{Name: s(name)})
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
func (a *authzService) UpdatePermissions(permissions *Permissions) error {
	// @check the account are ok
	if err := validatePermissions(permissions); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("failed to update permissions, permissions are invalid")

		return err
	}
	a.Lock()
	defer a.Unlock()

	a.permissions = permissions

	return nil
}

// getPermissions returns the permissions for the principal
func (a *authzService) getPermissions() *Permissions {
	a.RLock()
	defer a.RUnlock()

	return a.permissions
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
