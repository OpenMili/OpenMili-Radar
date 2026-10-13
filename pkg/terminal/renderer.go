// Package terminal renders compact, aligned reports for a terminal.
package terminal

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/mattn/go-runewidth"
)

// Tone describes the meaning of a result, independently of its wording.
type Tone string

const (
	ToneNeutral Tone = "neutral"
	ToneSuccess Tone = "success"
	ToneBlocked Tone = "blocked"
	ToneWarning Tone = "warning"
	ToneInfo    Tone = "info"
)

// Cell is one result in a two-column table. Detail is a short value, such as latency.
// Full evidence belongs in the machine-readable report rather than this compact row.
type Cell struct {
	Name   string
	Status string
	Detail string
	Tone   Tone
}

// Pair contains the left and right results on one table row.
type Pair struct {
	Left  Cell
	Right Cell
}

// Section groups paired results under two headings.
type Section struct {
	LeftTitle  string
	RightTitle string
	Rows       []Pair
}

// Report contains a title, exit summary, result tables, and notes.
type Report struct {
	Title    string
	Summary  []string
	Sections []Section
	Footer   []string
}

// Options controls table width and semantic colors. A zero Width means 80 columns.
// Callers should enable Color only for a terminal that supports ANSI colors.
type Options struct {
	Width int
	Color bool
}

// ErrUnsupportedWidth is returned for a width other than 80 or 100.
var ErrUnsupportedWidth = errors.New("terminal width must be 80 or 100")

var textWidth = func() *runewidth.Condition {
	c := runewidth.NewCondition()
	// Keep the documented width deterministic across OS locales: CJK is wide,
	// while ambiguous characters (including the ellipsis) use one column.
	c.EastAsianWidth = false
	return c
}()

type layout struct {
	cellWidth   int
	nameWidth   int
	statusWidth int
	detailWidth int
}

// Render writes a report using exactly four spaces between table columns.
// Every table heading and result row occupies exactly Width display columns.
// Names and detail values are truncated; status text is always preserved.
// Input escape sequences and control characters are removed before rendering.
func Render(w io.Writer, report Report, options Options) error {
	width := options.Width
	if width == 0 {
		width = 80
	}
	if width != 80 && width != 100 {
		return ErrUnsupportedWidth
	}
	if w == nil {
		return errors.New("terminal writer is nil")
	}

	var output strings.Builder
	appendWrapped(&output, report.Title, width)
	for _, summary := range report.Summary {
		appendWrapped(&output, summary, width)
	}
	for i, section := range report.Sections {
		l, err := sectionLayout(section, (width-4)/2)
		if err != nil {
			return fmt.Errorf("terminal section %d: %w", i+1, err)
		}
		if output.Len() > 0 {
			output.WriteByte('\n')
		}
		output.WriteString(renderHeading(section.LeftTitle, l))
		output.WriteString("    ")
		output.WriteString(renderHeading(section.RightTitle, l))
		output.WriteByte('\n')
		for _, pair := range section.Rows {
			output.WriteString(renderCell(pair.Left, l, options.Color))
			output.WriteString("    ")
			output.WriteString(renderCell(pair.Right, l, options.Color))
			output.WriteByte('\n')
		}
	}
	if len(report.Footer) > 0 && output.Len() > 0 {
		output.WriteByte('\n')
	}
	for _, note := range report.Footer {
		appendWrapped(&output, note, width)
	}
	result := output.String()
	n, err := io.WriteString(w, result)
	if err != nil {
		return fmt.Errorf("write terminal report: %w", err)
	}
	if n != len(result) {
		return fmt.Errorf("write terminal report: %w", io.ErrShortWrite)
	}
	return nil
}

func sectionLayout(section Section, cellWidth int) (layout, error) {
	statusWidth := 10
	for _, pair := range section.Rows {
		for _, cell := range []Cell{pair.Left, pair.Right} {
			if n := textWidth.StringWidth(cleanLine(cell.Status)); n > statusWidth {
				statusWidth = n
			}
		}
	}
	// A name needs at least one column and the colon needs two. If even that
	// cannot fit, report the invalid input instead of hiding part of a status.
	if statusWidth > cellWidth-3 {
		return layout{}, fmt.Errorf("status needs %d columns; cell allows at most %d", statusWidth, cellWidth-3)
	}
	detailWidth := 7
	if available := cellWidth - statusWidth - 4; detailWidth > available {
		detailWidth = available
	}
	if detailWidth < 0 {
		detailWidth = 0
	}
	nameWidth := cellWidth - 2 - statusWidth
	if detailWidth > 0 {
		nameWidth -= detailWidth + 1
	}
	return layout{cellWidth, nameWidth, statusWidth, detailWidth}, nil
}

func renderCell(cell Cell, l layout, useColor bool) string {
	if cell.Name == "" && cell.Status == "" && cell.Detail == "" {
		return strings.Repeat(" ", l.cellWidth)
	}
	var row strings.Builder
	row.WriteString(fit(cell.Name, l.nameWidth))
	row.WriteString(": ")
	row.WriteString(paint(fit(cell.Status, l.statusWidth), cell.Tone, useColor))
	if l.detailWidth > 0 {
		row.WriteByte(' ')
		row.WriteString(fit(cell.Detail, l.detailWidth))
	}
	return row.String()
}

func renderHeading(title string, l layout) string {
	if title = cleanLine(title); title == "" {
		return strings.Repeat(" ", l.cellWidth)
	}
	var header strings.Builder
	name := title
	if l.nameWidth >= 5 {
		name = "【" + textWidth.Truncate(title, l.nameWidth-4, "…") + "】"
	}
	header.WriteString(fit(name, l.nameWidth))
	header.WriteString("  ")
	header.WriteString(fit("[状态]", l.statusWidth))
	if l.detailWidth > 0 {
		header.WriteByte(' ')
		header.WriteString(fit("[延迟]", l.detailWidth))
	}
	return header.String()
}

func fit(value string, width int) string {
	value = cleanLine(value)
	if textWidth.StringWidth(value) > width {
		value = textWidth.Truncate(value, width, "…")
	}
	return value + strings.Repeat(" ", width-textWidth.StringWidth(value))
}

func appendWrapped(output *strings.Builder, value string, width int) {
	if value == "" {
		return
	}
	for _, line := range strings.Split(stripANSI(value), "\n") {
		output.WriteString(textWidth.Wrap(cleanLine(line), width))
		output.WriteByte('\n')
	}
}

// DisplayWidth counts terminal display columns, excluding ANSI escape sequences.
// It is intended for a single line.
func DisplayWidth(value string) int {
	return textWidth.StringWidth(cleanLine(value))
}

func cleanLine(value string) string {
	var clean strings.Builder
	for _, r := range stripANSI(value) {
		switch r {
		case '\r', '\n', '\t':
			clean.WriteByte(' ')
		default:
			if !unicode.IsControl(r) {
				clean.WriteRune(r)
			}
		}
	}
	return clean.String()
}

// stripANSI removes CSI colors/cursor instructions and OSC title/hyperlink
// sequences so strings obtained from remote pages cannot control the terminal.
func stripANSI(value string) string {
	var clean strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\x1b' {
			clean.WriteByte(value[i])
			i++
			continue
		}
		i++
		if i >= len(value) {
			break
		}
		switch value[i] {
		case '[':
			i++
			for i < len(value) {
				b := value[i]
				i++
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
		case ']':
			i++
			for i < len(value) {
				if value[i] == '\a' {
					i++
					break
				}
				if value[i] == '\x1b' && i+1 < len(value) && value[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		default:
			// Consume the final byte of a two-byte escape sequence.
			i++
		}
	}
	return clean.String()
}
