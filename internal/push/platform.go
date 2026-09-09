package push

import (
	"context"
	"errors"
)

// Platforms keeps delivery services isolated. A missing Android provider must
// never fall back to APNs or acknowledge an unsent notification.
type Platforms struct{ IOS, Android Service }

func ForPlatform(service Service, platform string) Service {
	if providers, ok := service.(*Platforms); ok {
		switch platform {
		case "ios":
			return providers.IOS
		case "android":
			return providers.Android
		}
		return Disabled{}
	}
	if platform == "ios" {
		return service
	}
	return Disabled{}
}

func EnabledPlatforms(service Service) []string {
	var enabled []string
	for _, platform := range []string{"ios", "android"} {
		if !IsDisabled(ForPlatform(service, platform)) {
			enabled = append(enabled, platform)
		}
	}
	return enabled
}

func (p *Platforms) Send(ctx context.Context, token, title, body string, data map[string]string, id string) error {
	if IsDisabled(p.IOS) {
		return errors.New("iOS push provider is disabled")
	}
	return p.IOS.Send(ctx, token, title, body, data, id)
}
func (p *Platforms) Close() {
	if p.IOS != nil {
		p.IOS.Close()
	}
	if p.Android != nil {
		p.Android.Close()
	}
}
