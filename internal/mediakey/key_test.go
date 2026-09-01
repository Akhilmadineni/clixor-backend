package mediakey

import (
	"strings"
	"testing"
)

func TestPublishedAndDeletionKeysAreIdempotent(t *testing.T) {
	staging := "conversations/conversation/media"
	published, err := Published(staging)
	if err != nil || published != "published/"+staging {
		t.Fatalf("published key=%q err=%v", published, err)
	}
	if second, err := Published(published); err != nil || second != published {
		t.Fatalf("republished key=%q err=%v", second, err)
	}
	keys, err := DeletionKeys(staging)
	if err != nil || len(keys) != 2 || keys[0] != staging || keys[1] != published {
		t.Fatalf("staging deletion keys=%v err=%v", keys, err)
	}
	keys, err = DeletionKeys(published)
	if err != nil || len(keys) != 2 || keys[0] != staging || keys[1] != published {
		t.Fatalf("published deletion keys=%v err=%v", keys, err)
	}
}

func TestPublishedRejectsInvalidOrOversizedKeys(t *testing.T) {
	for _, key := range []string{
		"", "/absolute", " leading", "trailing ", "embedded\ncontrol", string([]byte{0xff}),
		strings.Repeat("a", 1024),
	} {
		if _, err := Published(key); err == nil {
			t.Fatalf("invalid key was accepted: %q", key)
		}
	}
}
