package httpapi

import (
	_ "embed"
	"net/http"
)

const universalLinksCacheControl = "public, max-age=3600"

// Apple accepts the association file at either of these fixed paths. Both are
// served directly so validation never depends on a redirect.
//
//go:embed universal-links/apple-app-site-association
var appleAppSiteAssociationDocument []byte

//go:embed universal-links/join.html
var joinLandingDocument []byte

func (s *Server) appleAppSiteAssociation(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", universalLinksCacheControl)
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(appleAppSiteAssociationDocument)
}

func (s *Server) joinLanding(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "+
			"form-action 'none'; frame-ancestors 'none'",
	)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(joinLandingDocument)
}
