package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadRootkitsFromBundledJSON(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "assets", "rootkits.json"))

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

func TestLoadRootkitsFromPythonSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "Rootkit_Analysis.py")
	content := `
self.TEST = {
    'name': 'Example Rootkit',
    'file': ['/tmp/example'],
    'dir': ['/etc/example'],
    'ksyms': ['hideme'],
}
self.LKM_BADNAMES = ['badmod']
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write python source: %v", err)
	}

	corpus, err := LoadRootkits(path)
	if err != nil {
		t.Fatalf("LoadRootkits returned error: %v", err)
	}
	if len(corpus.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(corpus.Rules))
	}
	if corpus.Rules[0].Name != "Example Rootkit" {
		t.Fatalf("unexpected rule name: %s", corpus.Rules[0].Name)
	}
	if len(corpus.LKMNames) != 1 || corpus.LKMNames[0] != "badmod" {
		t.Fatalf("unexpected lkm names: %#v", corpus.LKMNames)
	}
}
