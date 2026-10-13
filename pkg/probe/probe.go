// Package probe implements the evidence-based webpage checks used by the CLI.
// It deliberately performs ordinary GET requests only: no login, forms,
// captcha bypass, playback or other actions that change a remote account.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OpenMili/OpenMili-Radar/pkg/catalog"
)

const (
	DefaultExitIPEndpoint = "https://api64.ipify.org?format=json"
	MaxBodyBytes          = 128 * 1024
)

// Status is intentionally descriptive. It is not a claim about why a site
// denied a request unless the response contains corresponding evidence.
type Status string

const (
	StatusOK       Status = "正常"
	StatusRisk     Status = "风控"
	StatusLimited  Status = "访问受限"
	StatusLogin    Status = "需登录"
	StatusTimeout  Status = "超时"
	StatusNetwork  Status = "网络错误"
	StatusUnknown  Status = "无法判定"
	StatusUntested Status = "未测试"
)

// Result contains the small evidence record shown by the terminal and the
// complete safe-to-serialize details emitted by --json.
type Result struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	URL         string        `json:"url"`
	FinalURL    string        `json:"final_url,omitempty"`
	Status      Status        `json:"status"`
	HTTPStatus  int           `json:"http_status,omitempty"`
	Title       string        `json:"title,omitempty"`
	BodySnippet string        `json:"body_snippet,omitempty"`
	Evidence    string        `json:"evidence,omitempty"`
	Error       string        `json:"error,omitempty"`
	Latency     time.Duration `json:"-"`
	LatencyMS   int64         `json:"latency_ms,omitempty"`
	TestedAt    time.Time     `json:"tested_at,omitempty"`
	Configured  bool          `json:"configured"`
	Started     bool          `json:"started"`
}

// ExitIPResult records an exit-IP check performed through the same client as
// webpage probes.
type ExitIPResult struct {
	IP        string        `json:"ip,omitempty"`
	Endpoint  string        `json:"endpoint"`
	Status    Status        `json:"status"`
	Evidence  string        `json:"evidence,omitempty"`
	Error     string        `json:"error,omitempty"`
	Latency   time.Duration `json:"-"`
	LatencyMS int64         `json:"latency_ms,omitempty"`
}

var titleRE = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)
var tagRE = regexp.MustCompile(`(?is)<[^>]+>`)

// RunAll executes configured probes concurrently, preserving catalog order.
// Unconfigured probes are returned as StatusUntested and are never requested.
func RunAll(ctx context.Context, client *http.Client, probes []catalog.Probe, workers int) []Result {
	if workers < 1 {
		workers = 1
	}
	results := make([]Result, len(probes))
	jobs := make(chan int)
	var wg sync.WaitGroup
	if workers > len(probes) {
		workers = len(probes)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				p := probes[idx]
				if strings.TrimSpace(p.URL) == "" {
					results[idx] = Result{ID: p.ID, Name: p.Name, Category: p.Category, URL: p.URL, Status: StatusUntested, Evidence: "未配置测试网址", Configured: false}
					continue
				}
				if ctx.Err() != nil {
					results[idx] = fromProbe(p, StatusUntested, "时间预算已到，未执行")
					continue
				}
				results[idx] = RunOne(ctx, client, p)
			}
		}()
	}
	for i := range probes {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func fromProbe(p catalog.Probe, status Status, evidence string) Result {
	return Result{ID: p.ID, Name: p.Name, Category: p.Category, URL: p.URL, Status: status, Evidence: evidence, Configured: p.URL != ""}
}

// RunOne performs one safe GET request and reads at most MaxBodyBytes.
func RunOne(ctx context.Context, client *http.Client, p catalog.Probe) Result {
	result := fromProbe(p, StatusUnknown, "")
	if client == nil {
		result.Status, result.Error = StatusNetwork, "HTTP 客户端未配置"
		return result
	}
	started := time.Now()
	result.Started = true
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		result.Status, result.Error = StatusNetwork, safeError(err)
		return finish(result, started)
	}
	req.Header.Set("User-Agent", "OpenMili/0.1 (+https://github.com/OpenMili/OpenMili-Radar)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			result.Status = StatusTimeout
		} else if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			result.Status = StatusTimeout
		} else {
			result.Status = StatusNetwork
		}
		result.Error = safeError(err)
		return finish(result, started)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if readErr != nil {
		if errors.Is(readErr, context.DeadlineExceeded) || isTimeout(readErr) || (errors.Is(readErr, context.Canceled) && ctx.Err() != nil) {
			result.Status = StatusTimeout
		} else {
			result.Status = StatusNetwork
		}
		result.Error = safeError(readErr)
		return finish(result, started)
	}
	result.HTTPStatus = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		result.FinalURL = resp.Request.URL.String()
	}
	result.Title = extractTitle(string(body))
	result.BodySnippet = extractSnippet(string(body), 240)
	result.Status, result.Evidence = classify(resp, body, p.ExpectedTitle)
	return finish(result, started)
}

func finish(result Result, started time.Time) Result {
	result.Latency = time.Since(started)
	result.LatencyMS = result.Latency.Milliseconds()
	result.TestedAt = time.Now().UTC()
	return result
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	// Go's URL errors can include a userinfo string in unusual caller URLs.
	// Catalog URLs are validated, but redact it as a defense in depth measure.
	msg := err.Error()
	if i := strings.Index(msg, "://"); i >= 0 {
		if at := strings.Index(msg[i+3:], "@"); at >= 0 {
			msg = msg[:i+3] + "***@" + msg[i+3+at+1:]
		}
	}
	return msg
}

func extractTitle(body string) string {
	match := titleRE.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(html.UnescapeString(tagRE.ReplaceAllString(match[1], " "))), " ")
}

func extractSnippet(body string, maxRunes int) string {
	if maxRunes < 1 {
		return ""
	}
	plain := html.UnescapeString(tagRE.ReplaceAllString(body, " "))
	plain = strings.Join(strings.Fields(plain), " ")
	runes := []rune(plain)
	if len(runes) <= maxRunes {
		return plain
	}
	return string(runes[:maxRunes]) + "…"
}

var evidenceWords = []string{
	"captcha", "recaptcha", "hcaptcha", "verify you are human", "are you human",
	"checking your browser", "just a moment", "cf-chl-", "challenge-platform",
	"access denied", "forbidden", "unusual traffic", "robot check", "automated access",
	"region unavailable", "not available in your country", "not available in your region",
	"geo-block", "geoblock", "请完成验证", "安全验证", "访问被拒绝", "访问受限", "机器人",
}

func classify(resp *http.Response, body []byte, expected []string) (Status, string) {
	text := strings.ToLower(string(body))
	title := strings.ToLower(extractTitle(string(body)))
	header := strings.ToLower(resp.Header.Get("Server") + " " + resp.Header.Get("X-Mitmproxy-Blocked-Reason"))
	combined := text + " " + title + " " + header
	for _, word := range evidenceWords {
		if strings.Contains(combined, word) {
			return StatusRisk, "页面包含风控/验证证据: " + word
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired:
		return StatusLogin, fmt.Sprintf("HTTP %d 要求认证", resp.StatusCode)
	case resp.StatusCode == http.StatusTooManyRequests:
		return StatusLimited, "HTTP 429 请求频率受限（仅表示当前请求受限）"
	case resp.StatusCode == http.StatusUnavailableForLegalReasons:
		return StatusLimited, "HTTP 451 区域或法律限制"
	case resp.StatusCode >= 400:
		return StatusLimited, fmt.Sprintf("HTTP %d 页面拒绝访问", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return StatusUnknown, fmt.Sprintf("HTTP %d 未形成成功页面证据", resp.StatusCode)
	}
	if len(expected) == 0 {
		return StatusOK, fmt.Sprintf("HTTP %d，页面成功返回", resp.StatusCode)
	}
	for _, want := range expected {
		want = strings.ToLower(strings.TrimSpace(want))
		if want != "" && (strings.Contains(title, want) || strings.Contains(text, want)) {
			return StatusOK, "页面包含预期站点标识: " + want
		}
	}
	return StatusUnknown, "页面已返回，但未找到预期站点标识"
}

// FetchExitIP checks the public IP over the supplied transport path.
func FetchExitIP(ctx context.Context, client *http.Client) ExitIPResult {
	return FetchExitIPAt(ctx, client, DefaultExitIPEndpoint)
}

// FetchExitIPAt is split out so offline tests can use a local httptest endpoint.
func FetchExitIPAt(ctx context.Context, client *http.Client, endpoint string) ExitIPResult {
	started := time.Now()
	out := ExitIPResult{Endpoint: endpoint, Status: StatusUnknown}
	if client == nil {
		out.Status, out.Error = StatusNetwork, "HTTP 客户端未配置"
		return finishExit(out, started)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		out.Status, out.Error = StatusNetwork, safeError(err)
		return finishExit(out, started)
	}
	req.Header.Set("User-Agent", "OpenMili/0.1")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			out.Status = StatusTimeout
		} else {
			out.Status = StatusNetwork
		}
		out.Error = safeError(err)
		return finishExit(out, started)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		if errors.Is(readErr, context.DeadlineExceeded) || isTimeout(readErr) || (errors.Is(readErr, context.Canceled) && ctx.Err() != nil) {
			out.Status = StatusTimeout
		} else {
			out.Status = StatusNetwork
		}
		out.Error = safeError(readErr)
		return finishExit(out, started)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		out.Status, out.Error = StatusNetwork, fmt.Sprintf("出口 IP 服务返回 HTTP %d", resp.StatusCode)
		return finishExit(out, started)
	}
	var payload struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(body, &payload)
	ip := strings.TrimSpace(payload.IP)
	if ip == "" {
		ip = strings.TrimSpace(string(body))
	}
	if net.ParseIP(ip) == nil {
		out.Status, out.Error = StatusUnknown, "出口 IP 服务返回格式无法识别"
		return finishExit(out, started)
	}
	out.IP, out.Status, out.Evidence = ip, StatusOK, "通过当前访问路径观测"
	return finishExit(out, started)
}

func finishExit(out ExitIPResult, started time.Time) ExitIPResult {
	out.Latency = time.Since(started)
	out.LatencyMS = out.Latency.Milliseconds()
	return out
}
