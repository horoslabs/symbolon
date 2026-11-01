package scan

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/horoslabs/symbolon/internal/probe"
)

// rawListener accepts TCP connections and hands each one to handle.
func rawListener(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	return ln.Addr().String()
}

func modernConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func assertNoNegotiation(t *testing.T, r *Report, reason string) {
	t.Helper()
	if hasFinding(r, High, "No support for TLS 1.2 or TLS 1.3") || hasFinding(r, Info, "TLS 1.3 not supported") {
		t.Errorf("protocol findings must not fire when nothing was negotiated: %+v", r.Findings)
	}
	var f *Finding
	for i := range r.Findings {
		if r.Findings[i].Title == "No TLS negotiation possible" {
			f = &r.Findings[i]
		}
	}
	if f == nil || f.Severity != Medium {
		t.Fatalf("missing [medium] No TLS negotiation possible: %+v", r.Findings)
	}
	if !strings.Contains(f.Detail, reason) {
		t.Errorf("detail %q should mention %q", f.Detail, reason)
	}
	for _, p := range r.Protocols {
		if p.Supported || p.ProbeError == "" || !p.NoAnswer {
			t.Errorf("%s: want unanswered with a probe_error, got %+v", p.Name, p)
		}
	}
	var buf bytes.Buffer
	r.WriteText(&buf)
	if !strings.Contains(buf.String(), "TLS 1.2  n/a (") {
		t.Errorf("text output should show n/a with a reason:\n%s", buf.String())
	}
}

func TestScanServerClosesImmediately(t *testing.T) {
	addr := rawListener(t, func(c net.Conn) { c.Close() })
	r, err := Scan(addr, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNegotiation(t, r, "closed by the server")
}

func TestScanServerNeverReplies(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	addr := rawListener(t, func(c net.Conn) {
		defer c.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	r, err := Scan(addr, Options{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	assertNoNegotiation(t, r, "timed out")
	if p := proto(r, probe.VersionTLS13); p.ProbeError != probe.ReasonTimeout {
		t.Errorf("TLS 1.3 probe_error = %q, want %q", p.ProbeError, probe.ReasonTimeout)
	}
}

func TestAlertReasonIsRecorded(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(24*time.Hour))
	r, err := Scan(serve(t, modernConfig(cert)), Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(r, Medium, "No TLS negotiation possible") {
		t.Error("a working server must not get the no-negotiation finding")
	}
	p := proto(r, probe.VersionSSL30)
	if !strings.HasPrefix(p.ProbeError, "alert protocol_version") || p.NoAnswer {
		t.Errorf("SSLv3: want protocol_version alert, got %+v", p)
	}
	if p := proto(r, probe.VersionTLS13); p.ProbeError != "" {
		t.Errorf("supported TLS 1.3 should have no probe_error: %q", p.ProbeError)
	}
}
