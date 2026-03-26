package rules

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadRootkits(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "GScan", "lib", "plugins", "Rootkit_Analysis.py"))

	corpus, err := LoadRootkits(path)
	if err != nil {
		t.Fatalf("LoadRootkits returned error: %v", err)
	}
	if len(corpus.Rules) == 0 {
		t.Fatal("expected rootkit rules to be loaded")
	}
	if len(corpus.LKMNames) == 0 {
		t.Fatal("expected suspicious LKM names to be loaded")
	}
}
