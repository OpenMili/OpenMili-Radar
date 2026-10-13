package catalog

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRegistryIntegrity(t *testing.T) {
	probes := All()
	if len(probes) != 319 {
		t.Fatalf("checklist item count = %d, want 319", len(probes))
	}
	categories := Categories()
	counts := []int{30, 6, 20, 50, 51, 30, 20, 10, 13, 16, 11, 11, 13, 14, 24}
	if len(categories) != len(counts) {
		t.Fatalf("category count = %d, want %d", len(categories), len(counts))
	}
	seen := make(map[string]bool)
	actualCounts := make(map[string]int)
	idPattern := regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$`)
	for _, probe := range probes {
		if !idPattern.MatchString(probe.ID) || seen[probe.ID] {
			t.Errorf("invalid or duplicate ID %q", probe.ID)
		}
		seen[probe.ID] = true
		if strings.TrimSpace(probe.Name) == "" || strings.TrimSpace(probe.Category) == "" {
			t.Errorf("missing label in %#v", probe)
		}
		actualCounts[probe.Category]++
		if probe.URL == "" {
			if probe.Default {
				t.Errorf("default item %q has no configured URL", probe.ID)
			}
			continue
		}
		parsed, err := url.Parse(probe.URL)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			t.Errorf("invalid webpage URL for %q: %q", probe.ID, probe.URL)
			continue
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Errorf("catalog URL must not contain credentials or session parameters: %q", probe.URL)
		}
		if len(probe.ExpectedTitle) == 0 {
			t.Errorf("configured item %q lacks expected page evidence", probe.ID)
		}
		for _, title := range probe.ExpectedTitle {
			if strings.TrimSpace(title) == "" {
				t.Errorf("empty title evidence for %q", probe.ID)
			}
		}
	}
	for i, category := range categories {
		if actualCounts[category] != counts[i] {
			t.Errorf("%q contains %d items, want %d", category, actualCounts[category], counts[i])
		}
	}
}

func TestFullRegistryIntegrity(t *testing.T) {
	probes := Full()
	if len(probes) != 522 {
		t.Fatalf("full checklist item count = %d, want 522", len(probes))
	}
	seen := make(map[string]bool, len(probes))
	for i, probe := range probes {
		if strings.TrimSpace(probe.ID) == "" || seen[probe.ID] {
			t.Fatalf("duplicate or empty full ID at %d: %q", i, probe.ID)
		}
		seen[probe.ID] = true
		if strings.TrimSpace(probe.Name) == "" || strings.TrimSpace(probe.Category) == "" {
			t.Fatalf("missing full label at %d: %#v", i, probe)
		}
		if i < 198 && probe.URL != "" {
			t.Fatalf("pre-web item %q unexpectedly has URL %q", probe.ID, probe.URL)
		}
	}
	if probes[0].Name != "本机系统时间 (协调世界时 / 北京时间)" {
		t.Fatalf("full registry does not start with chapter 1: %q", probes[0].Name)
	}
	if probes[198].Name != All()[0].Name {
		t.Fatalf("chapter 12 does not follow the 198 pre-web items")
	}
	if probes[len(probes)-1].Name != "全网综合风险等级评定与原路退款判定标准" {
		t.Fatalf("full registry does not end with chapter 13")
	}
}

func TestDefaultSubset(t *testing.T) {
	all := make(map[string]Probe)
	for _, probe := range All() {
		all[probe.ID] = probe
	}
	probes := Default()
	if len(probes) != 18 {
		t.Fatalf("default count = %d, want 18", len(probes))
	}
	for _, probe := range probes {
		original, exists := all[probe.ID]
		if !exists || !original.Default || probe.URL == "" {
			t.Errorf("default probe %q is not a configured registry member", probe.ID)
		}
	}
}

func TestCopiesAreIndependent(t *testing.T) {
	first := All()
	first[0].Name = "modified name"
	first[0].ExpectedTitle[0] = "modified title"
	second := All()
	if second[0].Name == "modified name" || second[0].ExpectedTitle[0] == "modified title" {
		t.Fatal("All exposes shared registry storage")
	}
	quick := Default()
	quick[0].ExpectedTitle[0] = "modified quick title"
	if Default()[0].ExpectedTitle[0] == "modified quick title" {
		t.Fatal("Default exposes shared title storage")
	}
	categories := Categories()
	categories[0] = "modified category"
	if Categories()[0] == "modified category" {
		t.Fatal("Categories exposes shared storage")
	}
}

func TestUnsupportedEndpointsRemainUnconfigured(t *testing.T) {
	unsupported := map[string]bool{
		"security-cloudflare": true, "security-akamai": true,
		"security-fastly": true, "security-datadome": true,
		"security-cloudfront":    true,
		"messaging-telegram-dc1": true, "messaging-telegram-dc2": true,
		"messaging-telegram-dc3": true, "messaging-telegram-dc4": true,
		"messaging-telegram-dc5": true,
		"messaging-apns":         true, "messaging-fcm": true, "dev-ghcr": true,
	}
	for _, probe := range All() {
		if unsupported[probe.ID] {
			if probe.URL != "" {
				t.Errorf("%q must require an explicitly configured page or separate protocol probe", probe.ID)
			}
			delete(unsupported, probe.ID)
		}
	}
	if len(unsupported) != 0 {
		t.Errorf("registry lacks required unconfigured items: %v", unsupported)
	}
}

// Keep item coverage and ordering tied to the source checklist, without any network request.
func TestMatchesSourceChecklist(t *testing.T) {
	path := filepath.Join("..", "..", "OpenMili_全量网络与风控探测大纲_CN.md")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("source checklist is not included in this source distribution")
	}
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	_, chapter, found := strings.Cut(text, "### 十二、")
	if !found {
		t.Fatal("source checklist has no industry chapter")
	}
	chapter, _, found = strings.Cut(chapter, "### 十三、")
	if !found {
		t.Fatal("source checklist has no closing chapter heading")
	}
	var names, categories []string
	for _, line := range strings.Split(chapter, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") {
			names = append(names, strings.TrimPrefix(line, "- "))
		}
		if strings.HasPrefix(line, "#### ") {
			_, name, ok := strings.Cut(strings.TrimPrefix(line, "#### "), ". ")
			if !ok {
				t.Fatalf("invalid category heading %q", line)
			}
			categories = append(categories, name)
		}
	}
	probes := All()
	if len(names) != len(probes) {
		t.Fatalf("registry has %d items; source checklist has %d", len(probes), len(names))
	}
	for i, name := range names {
		if probes[i].Name != name {
			t.Errorf("item %d = %q, want checklist label %q", i, probes[i].Name, name)
		}
	}
	actualCategories := Categories()
	if len(actualCategories) != len(categories) {
		t.Fatalf("registry has %d categories; source has %d", len(actualCategories), len(categories))
	}
	for i, category := range categories {
		if actualCategories[i] != category {
			t.Errorf("category %d = %q, want %q", i, actualCategories[i], category)
		}
	}
}
