// compliance is a host-local operator tool. It exposes no public admin API.
// Database credentials must come from the operator's secret environment, never flags.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Akhilmadineni/clixor-backend/internal/compliance"
	"github.com/Akhilmadineni/clixor-backend/internal/store/postgres"
)

func run() error {
	action := flag.String("action", "queue", "queue or review")
	limit := flag.Int("limit", 50, "maximum open cases, 1–100")
	details := flag.Bool("include-sensitive-details", false, "explicitly include contact and report content in queue output")
	flag.Parse()
	if *action != "queue" && *action != "review" {
		return errors.New("action must be queue or review")
	}
	url := os.Getenv("CLUSTER_DATABASE_URL")
	if url == "" {
		return errors.New("CLUSTER_DATABASE_URL must be supplied through the secret environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := postgres.OpenWithPool(ctx, url, false, 2, 0)
	if err != nil {
		return errors.New("database connection or schema validation failed")
	}
	defer s.Close()
	repo := s.Compliance()
	if *action == "queue" {
		cases, err := repo.ListCases(ctx, *limit)
		if err != nil {
			return errors.New("could not read review queue")
		}
		encoder := json.NewEncoder(os.Stdout)
		for _, c := range cases {
			// No case secrets, reporter contacts, or free text in default output.
			if *details {
				err = encoder.Encode(c)
			} else {
				err = encoder.Encode(struct {
					compliance.CaseStatus
					Category string `json:"category"`
					Overdue  bool   `json:"overdue"`
				}{c.Public(), c.Category, c.ReviewDueAt != nil && time.Now().After(*c.ReviewDueAt)})
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	var review compliance.Review
	d := json.NewDecoder(io.LimitReader(os.Stdin, 16<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&review); err != nil {
		return errors.New("review must be a valid JSON object on stdin")
	}
	if err = d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("one review object is required")
	}
	if err = repo.Review(ctx, review); err != nil {
		return fmt.Errorf("review not applied: %w", err)
	}
	_, err = fmt.Fprintln(os.Stdout, "Review recorded. No content, account, or privacy data was automatically changed.")
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
