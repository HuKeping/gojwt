package server

import (
	"net/http"

	"github.com/HuKeping/gojwt/handlers"

	"github.com/gorilla/mux"
)

// MainHandler returns what we support for now.
func MainHandler() http.Handler {
	r := mux.NewRouter()

	// we always want a ping
	r.Methods(http.MethodGet).Path("/v1/ping").HandlerFunc(handlers.Ping)

	// retrieve JWT
	r.Methods(http.MethodPost).Path("/v1/jwt").HandlerFunc(handlers.RetrieveJWT)

	return r
}
