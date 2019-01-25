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
	"strings"
)

// contains checks if the string exists in a list
func contains(v string, list []string) bool {
	if v == "*" {
		return true
	}
	for _, x := range list {
		if x == "*" {
			return true
		}
		if strings.ToLower(x) == strings.ToLower(v) {
			return true
		}
	}

	return false
}
