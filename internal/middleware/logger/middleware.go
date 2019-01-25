/*
Copyright 2018 Appvia Ltd All rights reserved.

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

package logger

import (
	"net/http"
	"net/http/httputil"
	"time"

	log "github.com/sirupsen/logrus"
)

type logging struct {
	next    http.Handler
	options *Options
}

// New creates and returns a logger middleware
func New(next http.Handler, opts ...Option) http.Handler {
	options := &Options{}
	for _, fn := range opts {
		fn(options)
	}

	return &logging{
		next:    next,
		options: options,
	}
}

func (l *logging) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var requestBody []byte
	// @step: read in the request body if required
	if l.options.withRequestLogging {
		dump, _ := httputil.DumpRequest(r, true)
		requestBody = dump
	}
	if l.options.withResponseLogging {

	}

	start := time.Now()
	wr := newWrapper(w)

	defer func() {
		fields := log.Fields{
			"host":     r.Host,
			"latency":  time.Now().Sub(start).String(),
			"method":   r.Method,
			"response": wr.status,
			"uri":      r.RequestURI,
		}
		if len(requestBody) > 0 {
			fields["request"] = requestBody
		}

		log.WithFields(fields).Info("served the http request")
	}()

	l.next.ServeHTTP(wr, r)
}
