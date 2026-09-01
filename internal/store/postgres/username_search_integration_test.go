package postgres

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/store"
	"github.com/google/uuid"
)

func TestPostgresUsernamePrefixSearchEscapesLikeMetacharacters(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	persistence, err := Open(ctx, databaseURL, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	createLegacy := func(username string) uuid.UUID {
		t.Helper()
		user, err := persistence.CreateUser(ctx, store.CreateUserParams{Email: uuid.NewString() + "@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		profile, _ := json.Marshal(map[string]string{"username": username})
		if _, err := persistence.pool.Exec(ctx, `UPDATE users SET profile=$2::jsonb WHERE id=$1`, user.ID, profile); err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	underscore := createLegacy("@literal_name")
	createLegacy("@literalXname")
	percent := createLegacy("@sale%team")
	createLegacy("@saleXteam")
	backslash := createLegacy(`@path\team`)
	createLegacy("@pathXteam")
	for _, test := range []struct {
		query string
		want  uuid.UUID
	}{
		{"literal_", underscore}, {"sale%", percent}, {`path\`, backslash},
	} {
		users, err := persistence.SearchUsersByUsername(ctx, test.query, 20)
		if err != nil {
			t.Fatalf("query %q: %v", test.query, err)
		}
		if len(users) != 1 || users[0].ID != test.want {
			t.Fatalf("query %q matched %+v, want only %s", test.query, users, test.want)
		}
	}
}
