package domain

import "strings"

func MobilePlatform(platform string) bool { return platform == "ios" || platform == "android" }

// FCM registration tokens are opaque and case-sensitive. Only APNs hex tokens
// (including historical platform-less internal callers) may be lowercased.
func NormalizePushToken(platform, token string) string {
	token = strings.TrimSpace(token)
	if platform != "android" {
		token = strings.ToLower(token)
	}
	return token
}
