package main

import "net/http"

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Render the homepage
	http.Error(w, "Homepage not implemented", http.StatusNotImplemented)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Render the admin page and register it behind admin-role middleware
	http.Error(w, "Admin page not implemented", http.StatusNotImplemented)
}
