package rules

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadYaraLite(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "GScan", "lib", "plugins", "webshell_rule"))

	corpus, err := LoadYaraLite(path)
	if err != nil {
		t.Fatalf("LoadYaraLite returned error: %v", err)
	}
	if len(corpus.Rules) == 0 {
		t.Fatal("expected yara-lite rules to be loaded")
	}
}
