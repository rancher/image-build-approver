// Command central-overrides plans or applies central Go module overrides.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	modulePattern             = regexp.MustCompile(`^golang\.org/x/[a-z][a-z0-9]*$`)
	versionPattern            = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	replacePattern            = regexp.MustCompile(`^(\s*-replace\s+)(golang\.org/x/[a-z][a-z0-9]*)=(golang\.org/x/[a-z][a-z0-9]*)@(v\d+\.\d+\.\d+)(\s*)$`)
	overridePattern           = regexp.MustCompile(`^\s*-replace\s+(golang\.org/x/[a-z][a-z0-9]*)\b`)
	goImagePattern            = regexp.MustCompile(`(?m)^\s*ARG\s+GO_IMAGE=(?:["']?)(rancher/hardened-build-base:v(1\.\d+\.\d+)b\d+)["']?\s*$`)
	goImageDeclarationPattern = regexp.MustCompile(`(?m)^\s*ARG\s+GO_IMAGE\b`)
	repositoryPattern         = regexp.MustCompile(`^image-build-[a-z0-9][a-z0-9-]*$`)
	cvePattern                = regexp.MustCompile(`^CVE-\d{4}-\d{4,}(?:, CVE-\d{4}-\d{4,})*$`)
	minimumGoPattern          = regexp.MustCompile(`^1\.\d+\.\d+$`)
)

type modulePolicy struct {
	TargetVersion string
	CVEs          string
	MinimumGo     string
}

type repositoryPolicy struct {
	Name  string
	Holds []string
}

type policy struct {
	Modules      map[string]modulePolicy
	Repositories []repositoryPolicy
}

type report struct {
	Repository string   `json:"repository"`
	Updates    []string `json:"updates"`
	Held       []string `json:"held"`
	Blocked    []string `json:"blocked"`
}

type replacement struct {
	index   int
	module  string
	current string
	match   []string
}

type candidate struct {
	replacement
	target string
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("expected object")
	}
	return object, nil
}

func exactKeys(object map[string]json.RawMessage, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, found := object[key]; !found {
			return false
		}
	}
	return true
}

func loadPolicy(path string) (policy, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return policy{}, err
	}
	root, err := decodeObject(contents)
	if err != nil || !exactKeys(root, "modules", "repositories") {
		return policy{}, errors.New("policy must contain modules and repositories")
	}
	var rawModules map[string]json.RawMessage
	var rawRepositories []json.RawMessage
	if json.Unmarshal(root["modules"], &rawModules) != nil || rawModules == nil || json.Unmarshal(root["repositories"], &rawRepositories) != nil || rawRepositories == nil {
		return policy{}, errors.New("modules must be an object and repositories an array")
	}
	result := policy{Modules: make(map[string]modulePolicy), Repositories: make([]repositoryPolicy, 0, len(rawRepositories))}
	for name, rawEntry := range rawModules {
		entry, entryErr := decodeObject(rawEntry)
		if entryErr != nil || !modulePattern.MatchString(name) || !exactKeys(entry, "targetVersion", "cves", "minimumGo") {
			return policy{}, fmt.Errorf("invalid module policy: %s", name)
		}
		var module modulePolicy
		if json.Unmarshal(entry["targetVersion"], &module.TargetVersion) != nil || json.Unmarshal(entry["cves"], &module.CVEs) != nil || json.Unmarshal(entry["minimumGo"], &module.MinimumGo) != nil {
			return policy{}, fmt.Errorf("invalid module policy: %s", name)
		}
		if !versionPattern.MatchString(module.TargetVersion) || !semver.IsValid(module.TargetVersion) {
			return policy{}, fmt.Errorf("unsupported version: %s", module.TargetVersion)
		}
		if !minimumGoPattern.MatchString(module.MinimumGo) || !semver.IsValid("v"+module.MinimumGo) {
			return policy{}, fmt.Errorf("unsupported minimumGo: %s", module.MinimumGo)
		}
		if !cvePattern.MatchString(module.CVEs) {
			return policy{}, fmt.Errorf("invalid CVEs for %s", name)
		}
		result.Modules[name] = module
	}
	seen := make(map[string]bool)
	for _, rawEntry := range rawRepositories {
		entry, entryErr := decodeObject(rawEntry)
		if entryErr != nil || !(exactKeys(entry, "name") || exactKeys(entry, "name", "holds")) {
			return policy{}, fmt.Errorf("invalid repository entry: %s", string(rawEntry))
		}
		var repository repositoryPolicy
		if json.Unmarshal(entry["name"], &repository.Name) != nil || !repositoryPattern.MatchString(repository.Name) || seen[repository.Name] {
			return policy{}, fmt.Errorf("invalid or duplicate repository: %s", repository.Name)
		}
		if rawHolds, found := entry["holds"]; found {
			if json.Unmarshal(rawHolds, &repository.Holds) != nil || repository.Holds == nil {
				return policy{}, fmt.Errorf("invalid holds for %s", repository.Name)
			}
		}
		holdsSeen := make(map[string]bool)
		for _, hold := range repository.Holds {
			if _, found := result.Modules[hold]; !found || holdsSeen[hold] {
				return policy{}, fmt.Errorf("invalid holds for %s", repository.Name)
			}
			holdsSeen[hold] = true
		}
		seen[repository.Name] = true
		result.Repositories = append(result.Repositories, repository)
	}
	return result, nil
}

func plan(currentPolicy policy, repositoryName, repositoryDir string) (report, *string, error) {
	result := report{Repository: repositoryName, Updates: []string{}, Held: []string{}, Blocked: []string{}}
	var repository *repositoryPolicy
	for index := range currentPolicy.Repositories {
		if currentPolicy.Repositories[index].Name == repositoryName {
			repository = &currentPolicy.Repositories[index]
			break
		}
	}
	if repository == nil {
		return result, nil, fmt.Errorf("repository not in policy: %s", repositoryName)
	}
	overridePath := filepath.Join(repositoryDir, "go-mod-overrides")
	contents, err := os.ReadFile(overridePath)
	if os.IsNotExist(err) {
		result.Blocked = append(result.Blocked, "missing root go-mod-overrides")
		return result, nil, nil
	}
	if err != nil {
		return result, nil, err
	}
	lines := strings.Split(string(contents), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	replacements := make([]replacement, 0)
	replacementByModule := make(map[string]bool)
	for index, line := range lines {
		match := replacePattern.FindStringSubmatch(line)
		override := overridePattern.FindStringSubmatch(line)
		if override != nil {
			if _, selected := currentPolicy.Modules[override[1]]; selected && (match == nil || match[2] != match[3]) {
				result.Blocked = append(result.Blocked, fmt.Sprintf("unsupported override for %s on line %d", override[1], index+1))
			}
		}
		if match == nil || match[2] != match[3] {
			continue
		}
		if _, selected := currentPolicy.Modules[match[2]]; !selected {
			continue
		}
		if replacementByModule[match[2]] {
			result.Blocked = append(result.Blocked, fmt.Sprintf("duplicate override for %s", match[2]))
			continue
		}
		replacementByModule[match[2]] = true
		replacements = append(replacements, replacement{index: index, module: match[2], current: match[4], match: match})
	}
	candidates := make([]candidate, 0)
	for _, item := range replacements {
		target := currentPolicy.Modules[item.module].TargetVersion
		held := false
		for _, hold := range repository.Holds {
			if hold == item.module {
				held = true
				break
			}
		}
		if held {
			result.Held = append(result.Held, fmt.Sprintf("%s: held at %s (target %s)", item.module, item.current, target))
			continue
		}
		if semver.Compare(item.current, target) < 0 {
			candidates = append(candidates, candidate{replacement: item, target: target})
		} else if semver.Compare(item.current, target) > 0 {
			result.Blocked = append(result.Blocked, fmt.Sprintf("%s: local %s exceeds target %s; no downgrade", item.module, item.current, target))
		}
	}
	if len(candidates) > 0 {
		dockerfile, dockerfileErr := os.ReadFile(filepath.Join(repositoryDir, "Dockerfile"))
		if os.IsNotExist(dockerfileErr) {
			result.Blocked = append(result.Blocked, "missing Dockerfile; cannot determine build Go version")
		} else if dockerfileErr != nil {
			return result, nil, dockerfileErr
		} else {
			images := goImagePattern.FindAllStringSubmatch(string(dockerfile), -1)
			if len(images) != 1 || len(goImageDeclarationPattern.FindAllString(string(dockerfile), -1)) != 1 {
				result.Blocked = append(result.Blocked, "cannot resolve a single literal hardened-build-base GO_IMAGE")
			} else {
				buildGo := "v" + images[0][2]
				for _, item := range candidates {
					required := "v" + currentPolicy.Modules[item.module].MinimumGo
					if semver.Compare(required, buildGo) > 0 {
						result.Blocked = append(result.Blocked, fmt.Sprintf("%s@%s requires Go %s; build image %s supplies Go %s", item.module, item.target, currentPolicy.Modules[item.module].MinimumGo, images[0][1], images[0][2]))
					}
				}
			}
		}
	}
	if len(result.Blocked) > 0 {
		return result, nil, nil
	}
	if len(candidates) == 0 {
		return result, nil, nil
	}
	for _, item := range candidates {
		result.Updates = append(result.Updates, fmt.Sprintf("%s: %s -> %s", item.module, item.current, item.target))
	}
	for index := len(candidates) - 1; index >= 0; index-- {
		item := candidates[index]
		lines[item.index] = item.match[1] + item.module + "=" + item.module + "@" + item.target + item.match[5]
		marker := "# Added by the central override in image-build-approver"
		annotation := []string{"# " + item.module + ": " + currentPolicy.Modules[item.module].CVEs + ".", marker}
		if item.index >= 2 && lines[item.index-1] == marker && strings.HasPrefix(lines[item.index-2], "# "+item.module+": ") {
			lines[item.index-2] = annotation[0]
			lines[item.index-1] = annotation[1]
		} else {
			lines = append(lines[:item.index], append(annotation, lines[item.index:]...)...)
		}
	}
	updated := strings.Join(lines, "\n") + "\n"
	return result, &updated, nil
}

func main() {
	policyPath := flag.String("policy", "", "path to the central override policy")
	repositoryName := flag.String("repo", "", "repository name")
	repositoryDir := flag.String("repo-dir", "", "repository checkout")
	apply := flag.Bool("apply", false, "write the planned changes")
	flag.Parse()
	if *policyPath == "" || *repositoryName == "" || *repositoryDir == "" {
		fmt.Fprintln(os.Stderr, "central overrides: --policy, --repo, and --repo-dir are required")
		os.Exit(2)
	}
	currentPolicy, err := loadPolicy(*policyPath)
	if err == nil {
		var updated *string
		var result report
		result, updated, err = plan(currentPolicy, *repositoryName, *repositoryDir)
		if err == nil && *apply && updated != nil {
			err = os.WriteFile(filepath.Join(*repositoryDir, "go-mod-overrides"), []byte(*updated), 0o644)
		}
		if err == nil {
			encoded, encodeErr := json.Marshal(result)
			if encodeErr != nil {
				err = encodeErr
			} else {
				fmt.Println(string(encoded))
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "central overrides: %v\n", err)
		os.Exit(1)
	}
}
