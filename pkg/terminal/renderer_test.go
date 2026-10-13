package terminal

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRenderTableWidths(t *testing.T) {
	for _, width := range []int{80, 100} {
		for _, useColor := range []bool{false, true} {
			t.Run(fmtName(width, useColor), func(t *testing.T) {
				report := Report{Sections: []Section{{
					LeftTitle: "学术科研", RightTitle: "人工智能",
					Rows: []Pair{{
						Left:  Cell{Name: "谷歌学术 Google Scholar", Status: "是", Detail: "128 ms", Tone: ToneSuccess},
						Right: Cell{Name: "Claude", Status: "否(风控)", Detail: "--", Tone: ToneBlocked},
					}, {
						Left:  Cell{Name: "超长中文平台名称" + strings.Repeat("中文", 30), Status: "无法判定", Detail: "99999 ms", Tone: ToneWarning},
						Right: Cell{Name: strings.Repeat("Long platform name ", 20), Status: "未测试", Tone: ToneWarning},
					}},
				}}}
				var output bytes.Buffer
				if err := Render(&output, report, Options{Width: width, Color: useColor}); err != nil {
					t.Fatal(err)
				}
				if !useColor && strings.Contains(output.String(), "\x1b") {
					t.Fatal("plain output contains ANSI")
				}
				if useColor && !strings.Contains(output.String(), "\x1b[1;32m") {
					t.Fatal("success color missing")
				}
				for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
					plain := stripANSI(line)
					if got := DisplayWidth(line); got != width {
						t.Fatalf("width = %d, want %d: %q", got, width, line)
					}
					left, rest := splitAtWidth(plain, (width-4)/2)
					if DisplayWidth(left) != (width-4)/2 || !strings.HasPrefix(rest, "    ") {
						t.Fatalf("invalid column gap: %q", line)
					}
				}
				if !strings.Contains(output.String(), "…") {
					t.Fatal("long names were not truncated")
				}
			})
		}
	}
}

func TestStatusIsPreserved(t *testing.T) {
	status := "未测试（代理不支持）"
	report := Report{Sections: []Section{{Rows: []Pair{{
		Left:  Cell{Name: strings.Repeat("长", 40), Status: status},
		Right: Cell{Name: "arXiv", Status: "正常"},
	}}}}}
	var output bytes.Buffer
	if err := Render(&output, report, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), status) {
		t.Fatalf("status was truncated: %q", output.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if DisplayWidth(line) != 80 {
			t.Fatalf("invalid width: %q", line)
		}
	}
}

func TestRejectImpossibleStatusWithoutPartialOutput(t *testing.T) {
	var output bytes.Buffer
	err := Render(&output, Report{Title: "title", Sections: []Section{{Rows: []Pair{{
		Left: Cell{Name: "site", Status: strings.Repeat("状态", 10)},
	}}}}}, Options{})
	if err == nil || output.Len() != 0 {
		t.Fatalf("err = %v; partial output = %q", err, output.String())
	}
}

func TestSanitizeANSIAndControls(t *testing.T) {
	report := Report{Sections: []Section{{Rows: []Pair{{Left: Cell{
		Name:   "\x1b[31m谷歌\x1b[0m\x1b]0;untrusted title\a学术\t",
		Status: "是\n\x1b[2J", Detail: "1\x00 ms",
	}}}}}}
	var output bytes.Buffer
	if err := Render(&output, report, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(output.String(), "\x1b\x00\t") || strings.Contains(output.String(), "untrusted") {
		t.Fatalf("unsafe control sequence leaked: %q", output.String())
	}
	if got := DisplayWidth("\x1b[1;32m中文e\u0301\x1b[0m"); got != 5 {
		t.Fatalf("ANSI/combining width = %d, want 5", got)
	}
}

func TestCombiningCharactersAndWrappedNotes(t *testing.T) {
	value := strings.Repeat("e\u0301", 20)
	truncated := fit(value, 5)
	if truncated != strings.Repeat("e\u0301", 4)+"…" {
		t.Fatalf("split combining sequence: %q", truncated)
	}
	var output bytes.Buffer
	if err := Render(&output, Report{
		Title:   strings.Repeat("出口体检", 20),
		Summary: []string{strings.Repeat("中文English ", 40)},
		Footer:  []string{strings.Repeat("e\u0301", 160)},
	}, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if DisplayWidth(line) > 80 {
			t.Fatalf("wrapped line exceeds width: %q", line)
		}
	}
}

func TestSemanticColor(t *testing.T) {
	for _, tc := range []struct {
		tone Tone
		code string
	}{
		{ToneSuccess, "\x1b[1;32m"},
		{ToneBlocked, "\x1b[1;31m"},
		{ToneWarning, "\x1b[1;33m"},
		{ToneInfo, "\x1b[1;36m"},
	} {
		got := paint("否（未列入）", tc.tone, true)
		if !strings.HasPrefix(got, tc.code) || !strings.HasSuffix(got, "\x1b[0m") {
			t.Fatalf("tone %s: %q", tc.tone, got)
		}
	}
}

func TestRenderErrors(t *testing.T) {
	if err := Render(io.Discard, Report{}, Options{Width: 79}); !errors.Is(err, ErrUnsupportedWidth) {
		t.Fatalf("invalid width error = %v", err)
	}
	if err := Render(nil, Report{}, Options{}); err == nil {
		t.Fatal("nil writer accepted")
	}
	expected := errors.New("writer closed")
	if err := Render(failedWriter{expected}, Report{Title: "title"}, Options{}); !errors.Is(err, expected) {
		t.Fatalf("write error = %v", err)
	}
	if err := Render(shortWriter{}, Report{Title: "title"}, Options{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v", err)
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func splitAtWidth(value string, width int) (string, string) {
	for i := range value {
		if DisplayWidth(value[:i]) == width {
			return value[:i], value[i:]
		}
	}
	return value, ""
}

func fmtName(width int, color bool) string {
	if width == 80 {
		if color {
			return "80-color"
		}
		return "80-plain"
	}
	if color {
		return "100-color"
	}
	return "100-plain"
}
