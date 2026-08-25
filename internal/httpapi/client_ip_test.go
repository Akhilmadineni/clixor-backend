package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/ratelimit"
)

func TestClientIPForRateLimit(t *testing.T) {
	t.Parallel()
	trusted := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("172.31.254.2/32"),
	}
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{name: "trusted loopback", remoteAddr: "127.0.0.1:54123", forwarded: "203.0.113.8", want: "203.0.113.8"},
		{name: "trusted docker gateway", remoteAddr: "172.31.254.2:41000", forwarded: "2001:db8::8", want: "2001:db8::8"},
		{name: "untrusted peer cannot spoof", remoteAddr: "198.51.100.20:443", forwarded: "203.0.113.9", want: "198.51.100.20"},
		{name: "malformed forwarded address", remoteAddr: "127.0.0.1:54123", forwarded: "203.0.113.8, 198.51.100.2", want: "127.0.0.1"},
		{name: "direct IPv6", remoteAddr: "[2001:db8::10]:443", want: "2001:db8::10"},
		{name: "mapped IPv4", remoteAddr: "[::ffff:192.0.2.44]:443", want: "192.0.2.44"},
		{name: "invalid peer is stable", remoteAddr: "not-an-address", forwarded: "203.0.113.8", want: "not-an-address"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "http://api.test/health/live", nil)
			request.RemoteAddr = test.remoteAddr
			if test.forwarded != "" {
				request.Header.Set(cloudflareConnectingIPHeader, test.forwarded)
			}
			if got := clientIPForRateLimit(request, trusted); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRateLimitSeparatesCloudflareVisitors(t *testing.T) {
	t.Parallel()
	server := &Server{
		limiter: ratelimit.NewMemory(),
		trustedProxyCIDRs: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
		},
	}
	handler := server.rateLimit("api-test", 1, time.Minute, true)(http.HandlerFunc(
		func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		},
	))

	request := func(visitor string) *http.Request {
		result := httptest.NewRequest(http.MethodGet, "http://api.test/health/live", nil)
		result.RemoteAddr = "127.0.0.1:51000"
		result.Header.Set(cloudflareConnectingIPHeader, visitor)
		return result
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request("203.0.113.1"))
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request("203.0.113.2"))
	repeated := httptest.NewRecorder()
	handler.ServeHTTP(repeated, request("203.0.113.1"))

	if first.Code != http.StatusNoContent || second.Code != http.StatusNoContent {
		t.Fatalf("distinct visitors shared a bucket: first=%d second=%d", first.Code, second.Code)
	}
	if repeated.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated visitor status = %d, want %d", repeated.Code, http.StatusTooManyRequests)
	}
}
