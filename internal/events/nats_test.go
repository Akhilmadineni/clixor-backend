package events

import "testing"

func TestFenceAcknowledgementIsBoundToRequestAndReplica(t *testing.T) {
	if !validFenceAck([]byte(`{"request_id":"request","replica_id":"replica"}`), "request", "replica") {
		t.Fatal("valid acknowledgement rejected")
	}
	for _, malformed := range [][]byte{
		[]byte(`{}`), []byte(`not-json`),
		[]byte(`{"request_id":"other","replica_id":"replica"}`),
		[]byte(`{"request_id":"request","replica_id":"other"}`),
	} {
		if validFenceAck(malformed, "request", "replica") {
			t.Fatalf("accepted malformed acknowledgement %s", malformed)
		}
	}
}
