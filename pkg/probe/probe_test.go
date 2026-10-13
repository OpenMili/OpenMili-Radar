package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenMili/OpenMili-Radar/pkg/catalog"
)

func TestRunOneUsesPageEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/challenge" {
			fmt.Fprint(w, `<html><title>Checking your browser</title><body>captcha</body></html>`)
			return
		}
		fmt.Fprint(w, `<html><title>Example site</title><body>Welcome</body></html>`)
	}))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	ok := RunOne(context.Background(), client, catalog.Probe{ID: "test-ok", Name: "Example", URL: server.URL, ExpectedTitle: []string{"Example site"}})
	if ok.Status != StatusOK || ok.HTTPStatus != http.StatusOK || ok.Title != "Example site" {
		t.Fatalf("normal result = %#v", ok)
	}
	risk := RunOne(context.Background(), client, catalog.Probe{ID: "test-risk", Name: "Challenge", URL: server.URL + "/challenge", ExpectedTitle: []string{"Challenge"}})
	if risk.Status != StatusRisk || risk.Evidence == "" {
		t.Fatalf("challenge result = %#v", risk)
	}
}

func TestRunAllDoesNotRequestUnconfigured(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `<title>Configured</title>`)
	}))
	defer server.Close()
	results := RunAll(context.Background(), &http.Client{Timeout: time.Second}, []catalog.Probe{
		{ID: "configured", Name: "Configured", URL: server.URL, ExpectedTitle: []string{"Configured"}},
		{ID: "missing", Name: "Missing"},
	}, 2)
	if len(results) != 2 || results[1].Status != StatusUntested || results[1].Started || calls != 1 {
		t.Fatalf("results=%#v calls=%d", results, calls)
	}
}

func TestFetchExitIPAt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"2001:db8::1"}`)
	}))
	defer server.Close()
	result := FetchExitIPAt(context.Background(), &http.Client{Timeout: time.Second}, server.URL)
	if result.Status != StatusOK || result.IP != "2001:db8::1" {
		t.Fatalf("exit result = %#v", result)
	}
}

func TestClickSameOriginLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/continue" {
			t.Fatalf("path = %s, want /continue", r.URL.Path)
		}
		fmt.Fprint(w, `<html><title>Continue page</title><body>Welcome after click</body></html>`)
	}))
	defer server.Close()
	doc, err := ClickSameOriginLink(context.Background(), &http.Client{Timeout: time.Second}, server.URL+"/page", "/continue#safe")
	if err != nil || doc.StatusCode != http.StatusOK || doc.Title != "Continue page" || doc.URL != server.URL+"/continue" {
		t.Fatalf("document=%#v err=%v", doc, err)
	}
	if !strings.Contains(doc.Text, "Welcome after click") {
		t.Fatalf("body snippet = %q", doc.Text)
	}
	if _, err := ClickSameOriginLink(context.Background(), &http.Client{Timeout: time.Second}, server.URL, "https://other.example/"); err == nil {
		t.Fatal("cross-origin link accepted")
	}
}
