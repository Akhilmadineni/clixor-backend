package httpapi

import (
	"net/http"
	"net/netip"
	"strings"
)

const cloudflareConnectingIPHeader = "CF-Connecting-IP"

func clientIPForRateLimit(request *http.Request, trustedProxyCIDRs []netip.Prefix) string {
	peer, ok := parsePeerIP(request.RemoteAddr)
	if !ok {
		return request.RemoteAddr
	}
	peer = peer.Unmap()
	if trustedProxy(peer, trustedProxyCIDRs) {
		forwarded, err := netip.ParseAddr(strings.TrimSpace(request.Header.Get(cloudflareConnectingIPHeader)))
		if err == nil {
			return forwarded.Unmap().String()
		}
	}
	return peer.String()
}

func parsePeerIP(remoteAddress string) (netip.Addr, bool) {
	if addressPort, err := netip.ParseAddrPort(remoteAddress); err == nil {
		return addressPort.Addr(), true
	}
	address, err := netip.ParseAddr(remoteAddress)
	return address, err == nil
}

func trustedProxy(address netip.Addr, trustedProxyCIDRs []netip.Prefix) bool {
	for _, prefix := range trustedProxyCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
