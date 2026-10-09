package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testPolicy(holds ...string) policy {
	return policy{
		Modules: map[string]modulePolicy{
			"golang.org/x/crypto": {TargetVersion: "v0.56.0", CVEs: "CVE-2026-56855, CVE-2026-78662", MinimumGo: "1.26.0"},
		},
		Repositories: []repositoryPolicy{{Name: "image-build-example", Holds: holds}},
	}
}

func writeTestFiles(t *testing.T, directory, dockerfile, overrides string) {
	t.Helper()
	if dockerfile != "" {
		if err := os.WriteFile(filepath.Join(directory, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if overrides != "" {
		if err := os.WriteFile(filepath.Join(directory, "go-mod-overrides"), []byte(overrides), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestLoadPolicy(t *testing.T) {
	valid := `{
"modules": {"golang.org/x/crypto": {"targetVersion": "v0.56.0", "cves": "CVE-2026-56855, CVE-2026-78662", "minimumGo": "1.26.0"}},
"repositories": [{"name": "image-build-example", "holds": ["golang.org/x/crypto"]}]
}`
	tests := []struct {
		name     string
		contents string
		want     policy
		wantErr  string
	}{
		{name: "valid policy", contents: valid, want: testPolicy("golang.org/x/crypto")},
		{name: "unknown root key", contents: `{"modules": {}, "repositories": [], "extra": true}`, wantErr: "policy must contain modules and repositories"},
		{name: "invalid module name", contents: `{"modules": {"example.com/module": {"targetVersion": "v0.1.0", "cves": "CVE-2026-56855", "minimumGo": "1.26.0"}}, "repositories": []}`, wantErr: "invalid module policy: example.com/module"},
		{name: "noncanonical module version", contents: `{"modules": {"golang.org/x/crypto": {"targetVersion": "v0.1.0-rc.1", "cves": "CVE-2026-56855", "minimumGo": "1.26.0"}}, "repositories": []}`, wantErr: "unsupported version: v0.1.0-rc.1"},
		{name: "invalid minimum Go version", contents: `{"modules": {"golang.org/x/crypto": {"targetVersion": "v0.1.0", "cves": "CVE-2026-56855", "minimumGo": "1.26"}}, "repositories": []}`, wantErr: "unsupported minimumGo: 1.26"},
		{name: "invalid CVE", contents: `{"modules": {"golang.org/x/crypto": {"targetVersion": "v0.1.0", "cves": "CVE-2026-1", "minimumGo": "1.26.0"}}, "repositories": []}`, wantErr: "invalid CVEs for golang.org/x/crypto"},
		{name: "hold must reference module", contents: `{"modules": {}, "repositories": [{"name": "image-build-example", "holds": ["golang.org/x/crypto"]}]}`, wantErr: "invalid holds for image-build-example"},
		{name: "duplicate repository", contents: `{"modules": {}, "repositories": [{"name": "image-build-example"}, {"name": "image-build-example"}]}`, wantErr: "invalid or duplicate repository: image-build-example"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, []byte(test.contents), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := loadPolicy(path)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("loadPolicy() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("loadPolicy() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestPlan(t *testing.T) {
	compatibleDockerfile := "ARG GO_IMAGE=rancher/hardened-build-base:v1.26.9b1\n"
	currentOverride := "-replace golang.org/x/crypto=golang.org/x/crypto@v0.52.0\n"
	tests := []struct {
		name           string
		currentPolicy  policy
		repositoryName string
		dockerfile     string
		overrides      string
		wantUpdates    []string
		wantHeld       []string
		wantBlocked    []string
		wantErr        string
		outputContains []string
		wantUpdated    bool
	}{
		{
			name:          "updates directive and adds annotation",
			currentPolicy: testPolicy(),
			dockerfile:    compatibleDockerfile,
			overrides:     currentOverride,
			wantUpdates:   []string{"golang.org/x/crypto: v0.52.0 -> v0.56.0"},
			wantUpdated:   true,
			outputContains: []string{
				"# golang.org/x/crypto: CVE-2026-56855, CVE-2026-78662.\n# Added by the central override in image-build-approver\n-replace golang.org/x/crypto=golang.org/x/crypto@v0.56.0",
			},
		},
		{
			name:          "refreshes existing canonical annotation",
			currentPolicy: testPolicy(),
			dockerfile:    compatibleDockerfile,
			overrides:     "# golang.org/x/crypto: CVE-2026-0000.\n# Added by the central override in image-build-approver\n" + currentOverride,
			wantUpdates:   []string{"golang.org/x/crypto: v0.52.0 -> v0.56.0"},
			wantUpdated:   true,
			outputContains: []string{
				"# golang.org/x/crypto: CVE-2026-56855, CVE-2026-78662.\n# Added by the central override in image-build-approver\n-replace golang.org/x/crypto=golang.org/x/crypto@v0.56.0",
			},
		},
		{
			name:          "held override",
			currentPolicy: testPolicy("golang.org/x/crypto"),
			overrides:     currentOverride,
			wantHeld:      []string{"golang.org/x/crypto: held at v0.52.0 (target v0.56.0)"},
			wantUpdated:   false,
		},
		{
			name:          "missing overrides file",
			currentPolicy: testPolicy(),
			wantBlocked:   []string{"missing root go-mod-overrides"},
			wantUpdated:   false,
		},
		{
			name:           "repository not in policy",
			currentPolicy:  testPolicy(),
			repositoryName: "image-build-other",
			wantErr:        "repository not in policy: image-build-other",
		},
		{
			name:          "unsupported replacement target",
			currentPolicy: testPolicy(),
			overrides:     "-replace golang.org/x/crypto=example.com/crypto@v0.52.0\n",
			wantBlocked:   []string{"unsupported override for golang.org/x/crypto on line 1"},
			wantUpdated:   false,
		},
		{
			name:          "duplicate selected override",
			currentPolicy: testPolicy(),
			dockerfile:    compatibleDockerfile,
			overrides:     currentOverride + currentOverride,
			wantBlocked:   []string{"duplicate override for golang.org/x/crypto"},
			wantUpdated:   false,
		},
		{
			name:          "no downgrade",
			currentPolicy: testPolicy(),
			dockerfile:    compatibleDockerfile,
			overrides:     "-replace golang.org/x/crypto=golang.org/x/crypto@v0.57.0\n",
			wantBlocked:   []string{"golang.org/x/crypto: local v0.57.0 exceeds target v0.56.0; no downgrade"},
			wantUpdated:   false,
		},
		{
			name:          "missing Dockerfile for update",
			currentPolicy: testPolicy(),
			overrides:     currentOverride,
			wantBlocked:   []string{"missing Dockerfile; cannot determine build Go version"},
			wantUpdated:   false,
		},
		{
			name:          "ambiguous Go image",
			currentPolicy: testPolicy(),
			dockerfile:    compatibleDockerfile + compatibleDockerfile,
			overrides:     currentOverride,
			wantBlocked:   []string{"cannot resolve a single literal hardened-build-base GO_IMAGE"},
			wantUpdated:   false,
		},
		{
			name:          "incompatible Go image",
			currentPolicy: policy{Modules: map[string]modulePolicy{"golang.org/x/crypto": {TargetVersion: "v0.56.0", CVEs: "CVE-2026-56855", MinimumGo: "1.27.0"}}, Repositories: []repositoryPolicy{{Name: "image-build-example"}}},
			dockerfile:    compatibleDockerfile,
			overrides:     currentOverride,
			wantBlocked:   []string{"golang.org/x/crypto@v0.56.0 requires Go 1.27.0; build image rancher/hardened-build-base:v1.26.9b1 supplies Go 1.26.9"},
			wantUpdated:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeTestFiles(t, directory, test.dockerfile, test.overrides)
			repositoryName := test.repositoryName
			if repositoryName == "" {
				repositoryName = "image-build-example"
			}

			got, updated, err := plan(test.currentPolicy, repositoryName, directory)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("plan() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(got.Updates, test.wantUpdates) || !equalStrings(got.Held, test.wantHeld) || !equalStrings(got.Blocked, test.wantBlocked) {
				t.Fatalf("plan() report = %#v, want updates=%#v held=%#v blocked=%#v", got, test.wantUpdates, test.wantHeld, test.wantBlocked)
			}
			if (updated != nil) != test.wantUpdated {
				t.Fatalf("plan() updated = %v, want present=%t", updated, test.wantUpdated)
			}
			if updated != nil {
				for _, expected := range test.outputContains {
					if !strings.Contains(*updated, expected) {
						t.Fatalf("updated overrides %q does not contain %q", *updated, expected)
					}
				}
			}
		})
	}
}
