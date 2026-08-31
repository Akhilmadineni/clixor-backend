package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAccountDeletionRetriesOnlyTransactionConflicts(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		if !isAccountDeletionRetryable(&pgconn.PgError{Code: code}) {
			t.Fatalf("SQLSTATE %s was not retryable", code)
		}
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505"},
		errors.New("network failed"),
		nil,
	} {
		if isAccountDeletionRetryable(err) {
			t.Fatalf("unexpected retry for %v", err)
		}
	}
}
