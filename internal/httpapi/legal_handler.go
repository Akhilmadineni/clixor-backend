package httpapi

import (
	_ "embed"
	"net/http"
)

//go:embed legal/index.html
var legalDocument []byte

func (s *Server) legal(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "+
			"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(legalDocument)
}
