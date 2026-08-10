package push

import (
	"context"
	"encoding/json"
)

type Service interface {
	Send(context.Context, string, string, string, map[string]string, string) error
	Close()
}

type Disabled struct{}

func (Disabled) Send(context.Context, string, string, string, map[string]string, string) error {
	return nil
}
func (Disabled) Close() {}

type Payload struct {
	APS  APS               `json:"aps"`
	Data map[string]string `json:"data,omitempty"`
}

type APS struct {
	Alert            Alert  `json:"alert"`
	Sound            string `json:"sound,omitempty"`
	MutableContent   int    `json:"mutable-content,omitempty"`
	ContentAvailable int    `json:"content-available,omitempty"`
}

type Alert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func EncodePayload(title, body string, data map[string]string) ([]byte, error) {
	return json.Marshal(Payload{
		APS: APS{
			Alert: Alert{Title: title, Body: body}, Sound: "default",
			MutableContent: 1, ContentAvailable: 1,
		},
		Data: data,
	})
}
