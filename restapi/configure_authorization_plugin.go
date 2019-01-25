// This file is safe to edit. Once it exists it will not be overwritten

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

package restapi

import (
	"crypto/tls"
	"net/http"

	errors "github.com/go-openapi/errors"
	runtime "github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	log "github.com/sirupsen/logrus"

	"github.com/appvia/anchore-rbac/internal/authorization"
	"github.com/appvia/anchore-rbac/internal/middleware/apierror"
	"github.com/appvia/anchore-rbac/internal/middleware/logger"
	"github.com/appvia/anchore-rbac/internal/middleware/recovery"
	"github.com/appvia/anchore-rbac/restapi/operations"
)

var (
	release = "v0.0.1"
)

type options struct {
	// ConfigFile is the configuration file with roles and domains
	ConfigFile string `long:"config-file" description:"the location of the account configuration file"`
	// DisableLogging disable the http logging
	DisableLogging bool `long:"disable-logging" description:"indicates http logging should be disabled"`
	// EnableRequestLogging indicates we should print the incoming request
	EnableRequestLogging bool `long:"enable-request-logging" description:"indicates we should print the incoming request"`
	// EnableResponseLogging indicates we should print the response
	EnableResponseLogging bool `long:"enable-response-logging" description:"indicates we should print the response"`
}

var apiOptions = &options{}

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)
}

func configureFlags(api *operations.AuthorizationPluginAPI) {
	api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{
		swag.CommandLineOptionsGroup{
			ShortDescription: "Additional options for the agent service",
			Options:          apiOptions,
		},
	}
}

func configureAPI(api *operations.AuthorizationPluginAPI) http.Handler {
	// @step: create the authorization server
	authz, err := authorization.NewFromReloadable(apiOptions.ConfigFile)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal("failed to initialize the authorization service")
	}

	// configure the api here
	api.ServeError = errors.ServeError

	api.JSONConsumer = runtime.JSONConsumer()
	api.JSONProducer = runtime.JSONProducer()

	api.DeleteDomainsHandler = operations.DeleteDomainsHandlerFunc(func(params operations.DeleteDomainsParams) middleware.Responder {
		if err := authz.DeleteDomain(params.Domain); err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewDeleteDomainsOK()
	})

	api.DeletePrincipalsHandler = operations.DeletePrincipalsHandlerFunc(func(params operations.DeletePrincipalsParams) middleware.Responder {
		if err := authz.DeletePrincipal(params.Principal); err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewDeletePrincipalsOK()
	})

	api.GetDomainsHandler = operations.GetDomainsHandlerFunc(func(params operations.GetDomainsParams) middleware.Responder {
		domains, err := authz.Domains()
		if err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewGetDomainsOK().WithPayload(domains)
	})

	api.GetHealthHandler = operations.GetHealthHandlerFunc(func(params operations.GetHealthParams) middleware.Responder {
		if err := authz.Health(); err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewGetHealthOK()
	})

	api.GetPrincipalsHandler = operations.GetPrincipalsHandlerFunc(func(params operations.GetPrincipalsParams) middleware.Responder {
		principals, err := authz.Principals()
		if err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewGetPrincipalsOK().WithPayload(principals)
	})

	api.PostAuthorizeHandler = operations.PostAuthorizeHandlerFunc(func(params operations.PostAuthorizeParams) middleware.Responder {
		decision, err := authz.Authorize(params.AuthzRequest)
		if err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewPostAuthorizeOK().WithPayload(decision)
	})

	api.PostDomainsHandler = operations.PostDomainsHandlerFunc(func(params operations.PostDomainsParams) middleware.Responder {
		if err := authz.AddDomain(params.Domain); err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewPostDomainsOK()
	})

	api.PostPrincipalsHandler = operations.PostPrincipalsHandlerFunc(func(params operations.PostPrincipalsParams) middleware.Responder {
		if err := authz.AddPrincipal(params.Principal); err != nil {
			return apierror.Error(http.StatusInternalServerError)
		}

		return operations.NewPostPrincipalsOK()
	})

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	h := recovery.New(handler)

	// @step: are we enabling logging middleware?
	if !apiOptions.DisableLogging {
		log.Info("enabling http logging middleware")
		h = logger.New(h, logger.WithRequestLogging(apiOptions.EnableRequestLogging))
	}

	return h
	return handler
}
