package config

import "testing"

func TestParseHourValidation(t *testing.T) {
	t.Parallel()

	if _, err := Parse([]string{"--hour=abc"}); err == nil {
		t.Fatal("expected invalid hour to fail")
	}
}

func TestParseSearchMode(t *testing.T) {
	t.Parallel()

	opts, err := Parse([]string{"--time=2026-03-20 00:00:00~2026-03-20 23:59:59"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !opts.SearchOnly {
		t.Fatal("expected search mode to be enabled")
	}
}
