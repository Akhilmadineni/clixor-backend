package mediakey

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const PublishedPrefix = "published/"

const maxObjectKeyBytes = 1024

// Published returns the deterministic object key that only the backend may
// create. Direct-upload capabilities always target the unprefixed staging key,
// so a replay can never overwrite the object served by download URLs.
func Published(stagingKey string) (string, error) {
	if err := Validate(stagingKey); err != nil {
		return "", err
	}
	if strings.HasPrefix(stagingKey, PublishedPrefix) {
		return stagingKey, nil
	}
	published := PublishedPrefix + stagingKey
	if len(published) > maxObjectKeyBytes {
		return "", errors.New("published media object key is too long")
	}
	return published, nil
}

// DeletionKeys covers both states of an upload whose database transaction may
// race an account or conversation deletion. It is symmetric because account
// deletion removes older outbox events containing the user's identity; a new
// event derived from the published key must therefore restore staging cleanup.
func DeletionKeys(objectKey string) ([]string, error) {
	published, err := Published(objectKey)
	if err != nil {
		return nil, err
	}
	if published == objectKey {
		staging := strings.TrimPrefix(objectKey, PublishedPrefix)
		if err := Validate(staging); err != nil {
			return nil, err
		}
		return []string{staging, objectKey}, nil
	}
	return []string{objectKey, published}, nil
}

func IsPublished(objectKey string) bool {
	return strings.HasPrefix(objectKey, PublishedPrefix)
}

func Validate(objectKey string) error {
	if objectKey == "" || len(objectKey) > maxObjectKeyBytes ||
		!utf8.ValidString(objectKey) || strings.HasPrefix(objectKey, "/") || strings.TrimSpace(objectKey) != objectKey {
		return errors.New("media object key is invalid")
	}
	for _, character := range objectKey {
		if character < 0x20 || character == 0x7f {
			return errors.New("media object key is invalid")
		}
	}
	return nil
}
