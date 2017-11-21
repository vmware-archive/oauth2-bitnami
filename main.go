/*
Copyright (c) 2017 Bitnami

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

package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/heptiolabs/healthcheck"
	"github.com/kubeapps/common/datastore"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

var dbSession datastore.Session
var sessionStore sessions.Store
var signingKey *string
var oauthClientID *string
var oauthClientSecret *string

func main() {
	dbHost := flag.String("mongo-host", "localhost:27017", "MongoDB host")
	dbName := flag.String("mongo-database", "ratesvc", "MongoDB database")
	signingKey = flag.String("jwt-key", "", "Secret used to sign JWT")
	oauthClientID = flag.String("client-id", "", "Client ID for OAuth")
	oauthClientSecret = flag.String("client-secret", "", "Client secret for OAuth")
	flag.Parse()

	if *signingKey == "" || *oauthClientID == "" || *oauthClientSecret == "" {
		log.Fatal("--jwt-key, --client-id and --client-secret must be set")
	}

	mongoConfig := datastore.Config{Host: *dbHost, Database: *dbName}
	var err error
	dbSession, err = datastore.NewSession(mongoConfig)
	if err != nil {
		log.WithFields(log.Fields{"host": *dbHost}).Fatal(err)
	}

	sessionStore = sessions.NewCookieStore([]byte(*signingKey))

	r := mux.NewRouter().StrictSlash(true)

	// Healthcheck
	health := healthcheck.NewHandler()
	r.Handle("/live", health)
	r.Handle("/ready", health)

	// Routes
	auth := r.PathPrefix("/auth").Subrouter()
	auth.Methods("GET").Path("").HandlerFunc(InitiateOAuth)
	auth.Methods("GET").Path("/bitnami/callback").HandlerFunc(BitnamiCallback)

	n := negroni.Classic()
	n.UseHandler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.WithFields(log.Fields{"addr": addr}).Info("Started oauth2-bitnami service")
	http.ListenAndServe(addr, n)
}
