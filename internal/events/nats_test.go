package events

import (
	"testing"
	"time"
)

func TestRealtimeLeaseAndFenceTimingContracts(t *testing.T) {
	const maximumGuardedAction = 10 * time.Second
	if realtimeOwnerAdmission+maximumGuardedAction >= realtimeOwnerTTL {
		t.Fatalf("local admission + drain=%s must be earlier than published TTL=%s",
			realtimeOwnerAdmission+maximumGuardedAction, realtimeOwnerTTL)
	}
	if realtimeOwnerRefresh >= realtimeOwnerAdmission {
		t.Fatalf("refresh=%s must occur before admission deadline=%s", realtimeOwnerRefresh, realtimeOwnerAdmission)
	}
	if realtimeFenceTTL <= 30*time.Second {
		t.Fatalf("fence TTL=%s must outlive the enforced mutation deadline", realtimeFenceTTL)
	}
}

func TestFenceAcknowledgementIsBoundToRequestAndReplica(t *testing.T) {
	if !validFenceAck([]byte(`{"request_id":"request","replica_id":"replica","generation":"generation"}`), "request", "replica", "generation") {
		t.Fatal("valid acknowledgement rejected")
	}
	for _, malformed := range [][]byte{
		[]byte(`{}`), []byte(`not-json`),
		[]byte(`{"request_id":"other","replica_id":"replica","generation":"generation"}`),
		[]byte(`{"request_id":"request","replica_id":"other","generation":"generation"}`),
		[]byte(`{"request_id":"request","replica_id":"replica","generation":"other"}`),
	} {
		if validFenceAck(malformed, "request", "replica", "generation") {
			t.Fatalf("accepted malformed acknowledgement %s", malformed)
		}
	}
}
