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
	"errors"
	"fmt"
)

// validateAccounts is responsible for checking the accounts
func validateAccounts(accounts *Accounts) error {
	if len(accounts.Roles) <= 0 {
		return errors.New("no role defined")
	}

	// @step: build a map of the roles
	roles := make(map[string]*Role, 0)
	for i, x := range accounts.Roles {
		if err := validateRole(x); err != nil {
			return fmt.Errorf("roles[%d] %s", i, err)
		}
		roles[x.Name] = x
	}

	encountered := make(map[string]*Principal, 0)

	// @step: iterate the principle and make sure they have a valid role
	for i, x := range accounts.Principals {

		// @check the principal is ok
		if err := validatePrincipal(x); err != nil {
			return fmt.Errorf("principals[%d] %s", i, err)
		}

		// @check the roles the principal has exist
		for _, r := range x.Roles {
			if _, found := roles[r]; !found {
				return fmt.Errorf("principals[%d].role %s does not exist", i, r)
			}
		}

		// @check the principal name is not already used
		if _, found := encountered[x.Name]; found {
			return fmt.Errorf("principals[%d].name %s already defined", i, x.Name)
		}

		encountered[x.Name] = x
	}

	return nil
}

// validatePrincipal is responsible for checking the principle
func validatePrincipal(principal *Principal) error {
	if principal.Name == "" {
		return errors.New("no name for principal")
	}

	return nil
}

// validateAccounts is responsible for checking the role
func validateRole(role *Role) error {
	if role.Name == "" {
		return errors.New("no role name defined")
	}
	if len(role.Actions) <= 0 {
		return errors.New("no role actions defined")
	}
	if len(role.Targets) <= 0 {
		return errors.New("no role target defined")
	}

	return nil
}
