package httpapi

import (
	_ "embed"
	"net/http"
)

//go:embed legal/index.html
var legalDocument []byte

func (s *Server) legal(w http.ResponseWriter, r *http.Request) {
	if r.Host == "clustr-api.atlanteanz.com" {
		// This permanent redirect is a public, non-user-specific document route.
		// Give it the same explicit cache contract as the destination so the edge
		// does not re-resolve an immutable hostname migration on every request.
		w.Header().Set("Cache-Control", "public, max-age=300")
		http.Redirect(w, r, "https://clixor.atlanteanz.com"+r.URL.RequestURI(), http.StatusPermanentRedirect)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(legalDocument)
}
