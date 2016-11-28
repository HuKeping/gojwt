package handlers

import (
	"fmt"
	"net/http"
)

// Ping usually be used for checking the connection, it returns
// 200-OK if everything is fine.
func Ping(w http.ResponseWriter, r *http.Request) {
	// Just a sanity check
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}
