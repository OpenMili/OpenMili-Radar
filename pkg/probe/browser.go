package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrBrowserUnavailable is returned by future browser-backed probes when an
// optional JavaScript runtime is not installed. The base CLI intentionally
// does not launch a browser or click page controls.
var ErrBrowserUnavailable = errors.New("可选浏览器运行时未配置")

// Browser is the narrow extension point for future, explicitly enabled
// browser checks. Implementations must use the same configured access path;
// this repository currently provides no implementation.
type Browser interface {
	Open(context.Context, string) (Document, error)
	Click(context.Context, string) (Document, error)
}

// Document is the evidence returned by an optional browser check.
type Document struct {
	URL        string
	Title      string
	Text       string
	StatusCode int
}

// ClickSameOriginLink performs the safe HTTP equivalent of clicking a normal
// HTML link. It never submits a form or runs JavaScript, and refuses to leave
// the page origin so a probe cannot accidentally trigger an unrelated host.
func ClickSameOriginLink(ctx context.Context, client *http.Client, pageURL, href string) (Document, error) {
	base, err := url.Parse(pageURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return Document{}, errors.New("页面地址无效")
	}
	target, err := base.Parse(href)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host != base.Host || target.Scheme != base.Scheme {
		return Document{}, errors.New("按钮链接必须是同源 HTTP(S) 地址")
	}
	target.Fragment = ""
	if client == nil {
		return Document{}, errors.New("HTTP 客户端未配置")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Document{}, err
	}
	req.Header.Set("User-Agent", "OpenMili/0.1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return Document{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return Document{}, err
	}
	finalURL := target.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	doc := Document{URL: finalURL, Title: extractTitle(string(body)), Text: extractSnippet(string(body), 240), StatusCode: resp.StatusCode}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return doc, fmt.Errorf("按钮链接返回 HTTP %d", resp.StatusCode)
	}
	return doc, nil
}

// NormalizeLinkText is a small helper for callers displaying a clicked
// document; it collapses whitespace without exposing control characters.
func NormalizeLinkText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
