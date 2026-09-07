package httpapi

import (
	_ "embed"
	"html/template"
	"net/http"
)

//go:embed support/index.html
var supportHTML string

//go:embed support/support.js
var supportJS []byte
var supportTemplate = template.Must(template.New("support").Parse(supportHTML))

func (s *Server) supportPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if !s.legalRelease.IntakeEnabled {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = supportTemplate.Execute(w, s.legalRelease)
}
func (s *Server) supportScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(supportJS)
}
