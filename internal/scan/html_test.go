package scan

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/horoslabs/symbolon/internal/certs"
)

func TestWriteHTML(t *testing.T) {
	yes := true
	r := &Report{
		Target:    "example.com",
		Host:      "example.com",
		Port:      443,
		ScannedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Protocols: []ProtocolResult{
			{Name: "TLS 1.2", Supported: true, ServerPrefer: &yes, Suites: []SuiteResult{
				{Name: "ECDHE-RSA-AES128-GCM-SHA256", Grade: "good", FS: true},
				{Name: "DES-CBC3-SHA", Grade: "weak"},
			}},
			{Name: "TLS 1.0"},
		},
		// Hostile server-controlled data must come out escaped.
		Cert: &certs.Info{Subject: `CN=<script>alert(1)</script>`, KeyType: "RSA", KeyBits: 2048, DaysLeft: 42},
		Findings: []Finding{
			{Severity: Medium, Title: "3DES accepted (SWEET32)", Detail: "DES-CBC3-SHA", Fix: "Disable the 3DES suites."},
			{Severity: Info, Title: "TLS 1.3 not supported"},
		},
	}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, []*Report{r}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"<!doctype html>",
		"example.com",
		"3DES accepted (SWEET32)",
		"DES-CBC3-SHA",
		`<span class="badge sev-medium">medium</span>`,
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "<script>") {
		t.Error("server-controlled data was not escaped")
	}
}

func TestWorstSeverity(t *testing.T) {
	r := &Report{Findings: []Finding{{Severity: Info}, {Severity: Low}, {Severity: High}}}
	if got := worstSeverity(r); got != High {
		t.Errorf("worst = %q, want %q", got, High)
	}
	if got := worstSeverity(&Report{Findings: []Finding{{Severity: Info}}}); got != "" {
		t.Errorf("worst with only info = %q, want empty", got)
	}
}
