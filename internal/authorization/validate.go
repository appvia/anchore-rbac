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

// validatePermissions is responsible for checking the permissions
func validatePermissions(permissions *Permissions) error {
	if len(permissions.Roles) <= 0 {
		return errors.New("no role defined")
	}

	// @step: build a map of the roles
	for name, x := range permissions.Roles {
		if err := validateRole(x); err != nil {
			return fmt.Errorf("roles.%s %s", name, err)
		}
	}

	// @step: iterate the principle and make sure they have a valid role
	for name, x := range permissions.Principals {
		// @check the principal is ok
		if err := validatePrincipal(x); err != nil {
			return fmt.Errorf("principals.%s %s", name, err)
		}

		// @check the roles the principal has exist
		for i, r := range x.Roles {
			if _, found := permissions.Roles[r]; !found {
				return fmt.Errorf("principals[%d].role %s does not exist", i, r)
			}
		}
	}

	return nil
}

// validatePrincipal is responsible for checking the principle
func validatePrincipal(principal *Principal) error {
	return nil
}

// validateAccounts is responsible for checking the role
func validateRole(role *Role) error {
	if len(role.Actions) <= 0 {
		return errors.New("no role actions defined")
	}
	if len(role.Targets) <= 0 {
		return errors.New("no role target defined")
	}

	return nil
}
