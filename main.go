package main

import (
	"net/http"

	"github.com/HuKeping/gojwt/server"

	"github.com/Sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	r := server.MainHandler()
	logrus.Fatal(http.ListenAndServe(":12321", r))
}
