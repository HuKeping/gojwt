package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/HuKeping/gojwt/jwt"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
)

// RetrieveJWT returns a JWT.
func RetrieveJWT(w http.ResponseWriter, r *http.Request) {
	// Just a sanity check
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	vars := mux.Vars(r)
	retrieveJWT(w, r, vars)
}

type Realm struct {
	Credential `json:"credential"`
	Scope      `json:"scope"`
}

type Credential struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type Scope struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

func retrieveJWT(w http.ResponseWriter, r *http.Request, vars map[string]string) {
	defer r.Body.Close()

	if err := parseForm(r); err != nil {
		logrus.Debugf("parse form error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := checkForJSON(r); err != nil {
		logrus.Debugf("check for json error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Content-Type specified must be 'application/json'")
		return
	}

	// Be notice that the `realm` could be nil
	realm, err := DecodeRealm(r.Body)
	if err != nil {
		logrus.Debugf("decode realm error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Bad Request.")
		return
	}

	// Verify the credential
	if err := authenticate(realm); err != nil {
		logrus.Debugf("authenticate failed, error:%v", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Bad Request.")
		return
	}

	t, err := jwt.GenerateJWT()
	if err != nil {
		logrus.Debugf("generate JWT failed, error:%v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, t)
	return
}

// always return nil for now
func authenticate(realm *Realm) error {
	if realm == nil {
		return fmt.Errorf("expect Realm got nil")
	}

	logrus.Debugf("received realm:%+v", realm)

	if realm.Name == "hukp" {
		return nil
	}

	return fmt.Errorf("Name is not 'hukp'")
}

// ensures the request form is parsed even with invalid content types.
// If we don't do this, POST method without Content-type (even with empty body) will fail
func parseForm(r *http.Request) error {
	if r == nil {
		return nil
	}

	if err := r.ParseForm(); err != nil && !strings.HasPrefix(err.Error(), "mime:") {
		return err
	}

	return nil
}

// make sure request's Content-Type is application/json
func checkForJSON(r *http.Request) error {
	ct := r.Header.Get("Content-Type")

	// No Content-Type header is ok as long as there's no Body
	if ct == "" {
		if r.Body == nil || r.ContentLength == 0 {
			return nil
		}
	}

	// Otherwise it better be json
	if MatchesContentType(ct, "application/json") {
		return nil
	}

	return fmt.Errorf("Content-Type specified (%s) must be 'application/json'", ct)
}

// MatchesContentType validates the content type against the expected one
func MatchesContentType(contentType, expectedType string) bool {
	mimetype, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		logrus.Errorf("error parsing media type: %s error: %v", contentType, err)
	}

	return err == nil && mimetype == expectedType
}

// DecodeRealm decodes a realm to realm structure.
//
// Be aware this function is not checking whether the resulted structs are
// nil or not, it's your business to do so.
func DecodeRealm(src io.Reader) (*Realm, error) {
	decoder := json.NewDecoder(src)

	realm := &Realm{}
	if err := decoder.Decode(realm); err != nil {
		return nil, err
	}

	return realm, nil
}
