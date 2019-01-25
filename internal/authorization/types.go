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

import "github.com/appvia/anchore-rbac/models"

// Interface is the contract ot the authorization service
type Interface interface {
	// Authorize is called to authorizer a request
	Authorize(*models.AuthorizationRequest) (*models.AuthorizationDecision, error)
	// AddDomain is called when adding a domain
	AddDomain(*models.Domain) error
	// DeleteDomain is called when deleting a domain
	DeleteDomain(*models.Domain) error
	// Domains is called to list all the domains
	Domains() (models.DomainList, error)
	// Principals is called to list all the principals
	Principals() (models.PrincipalList, error)
	// AddPrincipal is called to add a principle
	AddPrincipal(*models.Principal) error
	// DeletePrincipal is called to delete a principal
	DeletePrincipal(*models.Principal) error
	// Health is called is check the status
	Health() error
	// UpdatePermissions allows you to update the accounts permisions
	UpdatePermissions(*Accounts) error
}

// Role defines the permissions of a role in the system
type Role struct {
	// Name is the name of the domain
	Name string `json:"name" yaml:"name"`
	// Actions is a collection of actions they can perform
	Actions []string `json:"actions" yaml:"actions"`
	// Targets is a collection of targets the actions can be applied
	Targets []string `json:"targets" yaml:"targets"`
}

// Principal defines the anchore account and the roles they have
type Principal struct {
	// Domains is a list of domains the principal exists in
	Domains []string `json:"domains" yaml:"domains"`
	// Name is the name of the domain / account
	Name string `json:"name" yaml:"name"`
	// Roles is a collection of roles they have
	Roles []string `json:"roles" yaml:"roles"`
}

// Accounts is the accounting format
type Accounts struct {
	// Roles is a map of roles and the permissions
	Roles []*Role `json:"roles" yaml:"roles"`
	// Principals is the map of domains and their roles
	Principals []*Principal `json:"principals" yaml:"principals"`
}
