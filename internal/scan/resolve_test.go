package scan

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingTLS serves TLS on addr and counts accepted connections, so tests
// can tell which IP every probe went to.
func countingTLS(t *testing.T, addr string, cfg *tls.Config) (*atomic.Int64, int, error) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	t.Cleanup(func() { ln.Close() })
	n := new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() {
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()
	return n, ln.Addr().(*net.TCPAddr).Port, nil
}

// fakeLookup makes every hostname resolve to ips for the test's duration.
func fakeLookup(t *testing.T, ips ...string) {
	t.Helper()
	orig := lookupIP
	t.Cleanup(func() { lookupIP = orig })
	lookupIP = func(context.Context, string) ([]net.IP, error) {
		var out []net.IP
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

// dualStack starts the same TLS server on 127.0.0.1 and [::1] with one port.
func dualStack(t *testing.T) (v4, v6 *atomic.Int64, port int) {
	t.Helper()
	cfg := modernConfig(selfSigned(t, time.Now().Add(24*time.Hour)))
	v4, port, err := countingTLS(t, "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	v6, _, err = countingTLS(t, net.JoinHostPort("::1", strconv.Itoa(port)), cfg)
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	return v4, v6, port
}

func TestScanPinsFirstIP(t *testing.T) {
	v4, v6, port := dualStack(t)
	// IPv6 first on purpose: IPv4 must be sorted ahead of it.
	fakeLookup(t, "::1", "127.0.0.1")

	r, err := Scan("multi.test:"+strconv.Itoa(port), Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "127.0.0.1" || r.Host != "multi.test" {
		t.Errorf("ip = %q host = %q, want 127.0.0.1 multi.test", r.IP, r.Host)
	}
	if !r.Negotiated() {
		t.Fatalf("expected a negotiated protocol: %+v", r.Protocols)
	}
	if v4.Load() == 0 || v6.Load() != 0 {
		t.Errorf("probes must all hit the pinned IP: v4=%d v6=%d", v4.Load(), v6.Load())
	}
}

func TestScanSkipsUnreachableIP(t *testing.T) {
	cfg := modernConfig(selfSigned(t, time.Now().Add(24*time.Hour)))
	v4, port, err := countingTLS(t, "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 127.0.0.1 is reachable; ::1 on the same port is not (nothing listens).
	fakeLookup(t, "127.0.0.1", "::1")
	r, err := Scan("multi.test:"+strconv.Itoa(port), Options{Timeout: time.Second})
	if err != nil || r.IP != "127.0.0.1" || v4.Load() == 0 {
		t.Fatalf("want report for 127.0.0.1, got %+v, %v", r, err)
	}
}

func TestScanNoReachableIP(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	fakeLookup(t, "127.0.0.1", "::1")
	_, err := Scan("multi.test:"+strconv.Itoa(port), Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected an error when no IP is reachable")
	}
	for _, ip := range []string{"127.0.0.1:", "::1:"} {
		if !strings.Contains(err.Error(), ip) {
			t.Errorf("error should list %s: %v", ip, err)
		}
	}
}

func TestScanAllIPs(t *testing.T) {
	v4, v6, port := dualStack(t)
	fakeLookup(t, "::1", "127.0.0.1")

	reps, err := ScanAll("multi.test:"+strconv.Itoa(port), Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(reps) != 2 {
		t.Fatalf("want 2 reports, got %d", len(reps))
	}
	if reps[0].IP != "127.0.0.1" || reps[1].IP != "::1" {
		t.Errorf("reports in wrong order: %s, %s", reps[0].IP, reps[1].IP)
	}
	for _, r := range reps {
		if !r.Negotiated() {
			t.Errorf("%s: expected a negotiated protocol", r.IP)
		}
	}
	if v4.Load() == 0 || v6.Load() == 0 {
		t.Errorf("each IP should be probed: v4=%d v6=%d", v4.Load(), v6.Load())
	}
}

func TestScanIPLiteralSkipsLookup(t *testing.T) {
	orig := lookupIP
	t.Cleanup(func() { lookupIP = orig })
	lookupIP = func(context.Context, string) ([]net.IP, error) {
		t.Error("lookup must not run for an IP target")
		return nil, nil
	}
	addr := serve(t, modernConfig(selfSigned(t, time.Now().Add(24*time.Hour))))
	r, err := Scan(addr, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "127.0.0.1" {
		t.Errorf("ip = %q", r.IP)
	}
}
