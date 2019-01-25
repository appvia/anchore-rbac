// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright 2018 Appvia Ltd All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// DeleteDomainsHandlerFunc turns a function with the right signature into a delete domains handler
type DeleteDomainsHandlerFunc func(DeleteDomainsParams) middleware.Responder

// Handle executing the request and returning a response
func (fn DeleteDomainsHandlerFunc) Handle(params DeleteDomainsParams) middleware.Responder {
	return fn(params)
}

// DeleteDomainsHandler interface for that can handle valid delete domains params
type DeleteDomainsHandler interface {
	Handle(DeleteDomainsParams) middleware.Responder
}

// NewDeleteDomains creates a new http.Handler for the delete domains operation
func NewDeleteDomains(ctx *middleware.Context, handler DeleteDomainsHandler) *DeleteDomains {
	return &DeleteDomains{Context: ctx, Handler: handler}
}

/*DeleteDomains swagger:route DELETE /domains deleteDomains

Delete information about a domain, if applicable

*/
type DeleteDomains struct {
	Context *middleware.Context
	Handler DeleteDomainsHandler
}

func (o *DeleteDomains) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDeleteDomainsParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
