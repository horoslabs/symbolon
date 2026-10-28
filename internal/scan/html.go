package scan

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed report.html.tmpl
var htmlTmplSrc string

// html/template escapes everything: certificate fields and error strings come
// from the scanned server and must be treated as hostile input.
var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"counts": severityCounts,
	"worst":  worstSeverity,
	"join":   strings.Join,
	"inc":    func(i int) int { return i + 1 },
}).Parse(htmlTmplSrc))

// WriteHTML renders all reports as a single self-contained HTML page
// (inline CSS, no scripts, no external resources).
func WriteHTML(w io.Writer, reports []*Report) error {
	return htmlTmpl.Execute(w, struct {
		Generated time.Time
		Reports   []*Report
	}{time.Now().UTC(), reports})
}

func severityCounts(r *Report) map[string]int {
	c := map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// worstSeverity returns the most severe non-info finding, or "" if none.
func worstSeverity(r *Report) string {
	worst := ""
	for _, f := range r.Findings {
		if f.Severity != Info && (worst == "" || Rank(f.Severity) < Rank(worst)) {
			worst = f.Severity
		}
	}
	return worst
}
