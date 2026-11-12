package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Snawoot/windscribe-proxy/wndclient"
)

func TestSaveStateTruncatesOldContent(t *testing.T) {
	f := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(f, make([]byte, 100000), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveState(f, &wndclient.WndClientState{}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(f); err != nil {
		t.Fatalf("state written over a longer file is unreadable: %v", err)
	}
}
