package testutil

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update", false, "update golden files")

// CompareGolden reads `testdata/golden/<name>.json`, compares it to `got`,
// and updates if -update is set.
func CompareGolden(t *testing.T, name string, got any) {
	t.Helper()

	path := filepath.Join("testdata", "golden", name+".json")

	gotBytes, _ := json.MarshalIndent(got, "", "  ")
	gotBytes = append(gotBytes, '\n')

	if *updateGolden {
		_ = os.WriteFile(path, gotBytes, 0o644)
		return
	}

	expectedBytes, _ := os.ReadFile(path)
	if !bytes.Equal(expectedBytes, gotBytes) {
		t.Errorf("golden mismatch for %s.\nExpected:\n%s\n\nGot:\n%s\n\nUpdate with: go test -update",
			name, expectedBytes, gotBytes)
	}
}
