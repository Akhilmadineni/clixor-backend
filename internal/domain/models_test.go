package domain

import (
	"encoding/json"
	"testing"
)

func TestPageMarshalJSONUsesEmptyArrayForNilItems(t *testing.T) {
	encoded, err := json.Marshal(Page[string]{})
	if err != nil {
		t.Fatalf("marshal empty page: %v", err)
	}

	const expected = `{"items":[]}`
	if string(encoded) != expected {
		t.Fatalf("empty page JSON = %s, want %s", encoded, expected)
	}
}
