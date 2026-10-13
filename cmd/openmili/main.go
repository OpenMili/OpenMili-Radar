package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/OpenMili/OpenMili-Radar/pkg/catalog"
	"github.com/OpenMili/OpenMili-Radar/pkg/probe"
	"github.com/OpenMili/OpenMili-Radar/pkg/terminal"
	"github.com/OpenMili/OpenMili-Radar/pkg/transport"
	"github.com/mattn/go-isatty"
)

type options struct {
	proxy      string
	full       bool
	noColor    bool
	timeoutRaw string
	width      int
	json       bool
}

type jsonReport struct {
	Version       string             `json:"version"`
	Mode          string             `json:"mode"`
	Proxy         string             `json:"access_path"`
	TimeoutMS     int64              `json:"request_timeout_ms"`
	BudgetMS      int64              `json:"budget_ms"`
	ExitBefore    probe.ExitIPResult `json:"exit_before"`
	ExitAfter     probe.ExitIPResult `json:"exit_after"`
	ExitChanged   bool               `json:"exit_changed"`
	TotalCatalog  int                `json:"catalog_total"`
	TotalSelected int                `json:"selected_total"`
	Configured    int                `json:"configured_total"`
	NotTested     int                `json:"untested_total"`
	Results       []probe.Result     `json:"results"`
	GeneratedAt   time.Time          `json:"generated_at"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("openmili", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var opt options
	fs.StringVar(&opt.proxy, "proxy", "", "前置代理，例如 socks5://127.0.0.1:10808 或 http://127.0.0.1:10808")
	fs.BoolVar(&opt.full, "full", false, "执行全部已配置网页探针（默认 15 秒预算）")
	fs.BoolVar(&opt.noColor, "no-color", false, "禁用 ANSI 颜色")
	fs.StringVar(&opt.timeoutRaw, "timeout", "5s", "单个请求超时，例如 5s 或 5（秒）")
	fs.IntVar(&opt.width, "width", 80, "双列终端宽度，只支持 80 或 100")
	fs.BoolVar(&opt.json, "json", false, "输出 JSON 报告")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(errOut, "未知参数: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if opt.width != 80 && opt.width != 100 {
		fmt.Fprintln(errOut, "--width 只支持 80 或 100")
		return 2
	}
	timeout, err := parseDuration(opt.timeoutRaw)
	if err != nil {
		fmt.Fprintf(errOut, "--timeout 无效: %v\n", err)
		return 2
	}
	pathDescription, err := transport.DescribeProxy(opt.proxy)
	if err != nil {
		fmt.Fprintf(errOut, "代理配置无效: %v\n", err)
		return 2
	}
	client, err := transport.NewClient(transport.Config{ProxyURL: opt.proxy, Timeout: timeout})
	if err != nil {
		fmt.Fprintf(errOut, "无法初始化访问路径: %v\n", err)
		return 2
	}
	defer client.CloseIdleConnections()

	selected := catalog.Default()
	mode := "default"
	budget := timeout
	if opt.full {
		selected = catalog.All()
		mode = "full"
		budget = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	// The same budget covers both exit-IP checks and webpage probes, so a
	// stalled exit service cannot silently extend the advertised runtime.
	exitBefore := checkExit(ctx, client, timeout)
	results := probe.RunAll(ctx, client, selected, 64)
	exitAfter := checkExit(ctx, client, timeout)
	cancel()

	configured, untested := 0, 0
	for _, r := range results {
		if r.Configured {
			configured++
		}
		if r.Status == probe.StatusUntested {
			untested++
		}
	}
	exitChanged := exitBefore.IP != "" && exitAfter.IP != "" && exitBefore.IP != exitAfter.IP
	if opt.json {
		return writeJSON(out, jsonReport{
			Version: "0.1.0", Mode: mode, Proxy: pathDescription,
			TimeoutMS: timeout.Milliseconds(), BudgetMS: budget.Milliseconds(),
			ExitBefore: exitBefore, ExitAfter: exitAfter, ExitChanged: exitChanged,
			TotalCatalog: len(catalog.All()), TotalSelected: len(selected), Configured: configured, NotTested: untested,
			Results: results, GeneratedAt: time.Now().UTC(),
		})
	}

	colorEnabled := !opt.noColor && (isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()))
	report := buildReport(mode, pathDescription, timeout, budget, exitBefore, exitAfter, exitChanged, selected, results, configured, untested)
	if err := terminal.Render(out, report, terminal.Options{Width: opt.width, Color: colorEnabled}); err != nil {
		fmt.Fprintf(errOut, "渲染报告失败: %v\n", err)
		return 1
	}
	return 0
}

func parseDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("不能为空")
	}
	if d, err := time.ParseDuration(raw); err == nil {
		if d > 0 {
			return d, nil
		}
	}
	var seconds float64
	if _, err := fmt.Sscanf(raw, "%f", &seconds); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second)), nil
	}
	return 0, errors.New("请使用正数秒数或带单位的时长（例如 5s）")
}

func checkExit(parent context.Context, client *http.Client, timeout time.Duration) probe.ExitIPResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return probe.FetchExitIP(ctx, client)
}

func writeJSON(w io.Writer, report jsonReport) int {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return 1
	}
	return 0
}

func buildReport(mode, path string, timeout, budget time.Duration, before, after probe.ExitIPResult, changed bool, selected []catalog.Probe, results []probe.Result, configured, untested int) terminal.Report {
	resultsByCategory := make(map[string][]probe.Result)
	categoryOrder := make([]string, 0)
	seen := make(map[string]bool)
	for _, result := range results {
		if !seen[result.Category] {
			seen[result.Category] = true
			categoryOrder = append(categoryOrder, result.Category)
		}
		resultsByCategory[result.Category] = append(resultsByCategory[result.Category], result)
	}
	configuredCatalog := 0
	for _, p := range selected {
		if p.URL != "" {
			configuredCatalog++
		}
	}
	summary := []string{
		fmt.Sprintf("访问模式：%s；路径：%s", modeLabel(mode), path),
		fmt.Sprintf("请求超时：%s；本次预算：%s；网页探针：%d（已配置 %d，未配置/未测试 %d）", timeout, budget, len(selected), configured, untested),
		fmt.Sprintf("清单总数：%d；当前模式可请求网址：%d", len(catalog.All()), configuredCatalog),
	}
	if before.IP != "" {
		summary = append(summary, fmt.Sprintf("开始出口 IPv%s：%s", ipFamily(before.IP), before.IP))
	} else {
		summary = append(summary, "开始出口 IP：未获取（"+exitReason(before)+")")
	}
	if after.IP != "" {
		summary = append(summary, fmt.Sprintf("结束出口 IPv%s：%s", ipFamily(after.IP), after.IP))
	} else {
		summary = append(summary, "结束出口 IP：未获取（"+exitReason(after)+")")
	}
	if changed {
		summary = append(summary, "警告：开始与结束出口 IP 不一致，本次结果不能合并为单一 IP 评级")
	}
	sections := make([]terminal.Section, 0, (len(categoryOrder)+1)/2)
	for i := 0; i < len(categoryOrder); i += 2 {
		leftCategory := categoryOrder[i]
		rightCategory := ""
		if i+1 < len(categoryOrder) {
			rightCategory = categoryOrder[i+1]
		}
		leftItems := resultsByCategory[leftCategory]
		rightItems := resultsByCategory[rightCategory]
		section := terminal.Section{LeftTitle: leftCategory, RightTitle: rightCategory}
		rowCount := len(leftItems)
		if len(rightItems) > rowCount {
			rowCount = len(rightItems)
		}
		for row := 0; row < rowCount; row++ {
			pair := terminal.Pair{}
			if row < len(leftItems) {
				pair.Left = toCell(leftItems[row])
			}
			if row < len(rightItems) {
				pair.Right = toCell(rightItems[row])
			}
			section.Rows = append(section.Rows, pair)
		}
		sections = append(sections, section)
	}
	footer := []string{
		"证据说明：网页状态只依据本次响应的状态码、标题和有限正文片段；数据库属性不参与实时网页结论。",
		"安全边界：仅执行普通 GET 和重定向跟随；不登录、不提交表单、不绕过验证码、不执行真实播放。",
	}
	return terminal.Report{Title: "OpenMili 出口 IP 实际使用体检", Summary: summary, Sections: sections, Footer: footer}
}

func modeLabel(mode string) string {
	if mode == "full" {
		return "全量网页实测"
	}
	return "默认重点网页实测"
}

func ipFamily(ip string) string {
	if strings.Contains(ip, ":") {
		return "6"
	}
	return "4"
}

func exitReason(result probe.ExitIPResult) string {
	if result.Error != "" {
		return result.Error
	}
	if result.Evidence != "" {
		return result.Evidence
	}
	return string(result.Status)
}

func toCell(result probe.Result) terminal.Cell {
	detail := "--"
	if result.Started {
		detail = fmt.Sprintf("%d ms", result.LatencyMS)
	}
	return terminal.Cell{Name: result.Name, Status: string(result.Status), Detail: detail, Tone: tone(result.Status)}
}

func tone(status probe.Status) terminal.Tone {
	switch status {
	case probe.StatusOK:
		return terminal.ToneSuccess
	case probe.StatusRisk, probe.StatusLimited:
		return terminal.ToneBlocked
	case probe.StatusLogin, probe.StatusTimeout, probe.StatusNetwork, probe.StatusUnknown, probe.StatusUntested:
		return terminal.ToneWarning
	default:
		return terminal.ToneNeutral
	}
}
