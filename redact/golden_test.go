package redact_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JAS0N-SMITH/redactlog/redact"
)

// update rewrites golden files with the actual output when -update is passed.
var update = flag.Bool("update", false, "update golden files with actual output")

// goldenCase is the schema for each golden test file.
type goldenCase struct {
	Input any `json:"input"`
	Want  any `json:"want"`
}

// TestGoldenPAN runs all testdata/golden/pci_*.json files through an Engine
// configured with PANDetector (no path rules). Payment files must have all
// PANs masked; negative files must be returned unchanged.
//
// Run with -update to regenerate the "want" fields from actual output:
//
//	go test ./redact/ -run TestGoldenPAN -update
func TestGoldenPAN(t *testing.T) {
	engine, err := redact.New(nil, redact.Options{
		Detectors: []redact.Detector{redact.PANDetector()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pattern := filepath.Join("..", "testdata", "golden", "pci_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no golden files found — testdata/golden may be empty")
	}

	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}

			var tc goldenCase
			if err := json.Unmarshal(data, &tc); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			got := engine.Redact(tc.Input)

			if *update {
				tc.Want = got
				out, err := json.Marshal(tc)
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				t.Logf("updated %s", path)
				return
			}

			if !deepEqual(got, tc.Want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(tc.Want, "", "  ")
				t.Errorf("golden mismatch for %s:\ngot:  %s\nwant: %s", name, gotJSON, wantJSON)
			}
		})
	}
}
