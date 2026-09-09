package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Configure before serving. Missing signing identity grants no app authority;
// never publish fabricated fingerprints or a default/debug package in production.
func (s *Server) ConfigureAndroidLinks(packageName string, fingerprints []string) error {
	if packageName != "" && !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`).MatchString(packageName) {
		return errors.New("invalid Android package name")
	}
	if len(fingerprints) > 20 || (len(fingerprints) > 0 && packageName == "") {
		return errors.New("invalid Android signing configuration")
	}
	canonical := make([]string, 0, len(fingerprints))
	seen := map[string]bool{}
	for _, fingerprint := range fingerprints {
		fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
		if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(fingerprint) {
			return errors.New("Android signing fingerprint must be SHA-256 colon-separated hex")
		}
		if !seen[fingerprint] {
			seen[fingerprint] = true
			canonical = append(canonical, fingerprint)
		}
	}
	if len(canonical) == 0 {
		s.androidLinks = []byte("[]")
		return nil
	}
	document, err := json.Marshal([]any{map[string]any{"relation": []string{"delegate_permission/common.handle_all_urls"}, "target": map[string]any{"namespace": "android_app", "package_name": packageName, "sha256_cert_fingerprints": canonical}}})
	if err == nil {
		s.androidLinks = document
	}
	return err
}

func (s *Server) androidAssetLinks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", universalLinksCacheControl)
	w.Header().Set("X-Clixor-Revision", buildRevision)
	document := s.androidLinks
	if len(document) == 0 {
		document = []byte("[]")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}
