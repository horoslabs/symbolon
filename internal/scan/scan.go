// Package scan orchestrates probing a TLS target: protocols, suites,
// preference order, certificate and findings.
package scan

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/horoslabs/symbolon/internal/certs"
	"github.com/horoslabs/symbolon/internal/probe"
)

// Options configures the scan.
type Options struct {
	Timeout time.Duration
	SNI     string // defaults to the target's host
}

// SuiteResult is a suite accepted by the server.
type SuiteResult struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Grade  string `json:"grade"`
	FS     bool   `json:"forward_secrecy"`
	DHBits int    `json:"dh_bits,omitempty"`
}

// ProtocolResult is the result for one protocol version.
type ProtocolResult struct {
	Name         string        `json:"name"`
	Version      uint16        `json:"-"`
	Supported    bool          `json:"supported"`
	Suites       []SuiteResult `json:"suites,omitempty"` // in the server's preference order
	ServerPrefer *bool         `json:"server_preference,omitempty"`
}

// Report is the full result for a target.
type Report struct {
	Target    string           `json:"target"`
	Host      string           `json:"host"`
	Port      int              `json:"port"`
	ScannedAt time.Time        `json:"scanned_at"`
	Protocols []ProtocolResult `json:"protocols"`
	Cert      *certs.Info      `json:"certificate,omitempty"`
	Findings  []Finding        `json:"findings"`
	Notes     []string         `json:"notes,omitempty"`
}

// SplitTarget splits host and port (443 by default).
func SplitTarget(target string) (string, int) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return target, 443
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return h, 443
	}
	return h, n
}

type versionSlot struct {
	res     ProtocolResult
	certs   [][]byte
	notes   []string
	dhBySID map[uint16]int
}

// Scan probes a target (host or host:port).
func Scan(target string, opt Options) (*Report, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	host, port := SplitTarget(target)
	sni := opt.SNI
	if sni == "" {
		sni = host
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	p := &probe.Prober{Addr: addr, SNI: sni, Timeout: opt.Timeout}

	// Connectivity check: if there's no TCP, there's no point continuing.
	c, err := net.DialTimeout("tcp", addr, opt.Timeout)
	if err != nil {
		return nil, err
	}
	c.Close()

	versions := []uint16{probe.VersionSSL30, probe.VersionTLS10, probe.VersionTLS11, probe.VersionTLS12, probe.VersionTLS13}
	slots := make([]versionSlot, len(versions))
	var wg sync.WaitGroup
	for i, v := range versions {
		wg.Add(1)
		go func(i int, v uint16) {
			defer wg.Done()
			slots[i] = scanVersion(p, v)
		}(i, v)
	}
	wg.Wait()

	r := &Report{
		Target:    target,
		Host:      host,
		Port:      port,
		ScannedAt: time.Now().UTC(),
	}
	var der [][]byte
	for _, s := range slots {
		r.Protocols = append(r.Protocols, s.res)
		r.Notes = append(r.Notes, s.notes...)
		if len(der) == 0 && len(s.certs) > 0 {
			der = s.certs
		}
	}
	if len(der) == 0 {
		der = fetchCert(addr, sni, opt.Timeout)
	}
	if len(der) > 0 {
		info, err := certs.Analyze(der, sni, r.ScannedAt)
		if err != nil {
			r.Notes = append(r.Notes, "could not analyze certificate: "+err.Error())
		} else {
			r.Cert = info
		}
	} else {
		r.Notes = append(r.Notes, "could not obtain the certificate")
	}
	r.Findings = Evaluate(r)
	return r, nil
}

func scanVersion(p *probe.Prober, ver uint16) versionSlot {
	slot := versionSlot{res: ProtocolResult{Name: probe.VersionName(ver), Version: ver}}
	all := probe.LegacySuites
	probeFn := func(s []probe.Suite) (probe.Result, error) { return p.Legacy(ver, s) }
	if ver == probe.VersionTLS13 {
		all = probe.TLS13Suites
		probeFn = p.TLS13
	}

	remaining := append([]probe.Suite(nil), all...)
	var accepted []probe.Suite
	for range all {
		if len(remaining) == 0 {
			break
		}
		res, err := probeFn(remaining)
		if err != nil {
			slot.notes = append(slot.notes, slot.res.Name+": "+err.Error())
			break
		}
		if !res.Supported || res.Version != ver {
			break
		}
		idx := -1
		for i, s := range remaining {
			if s.ID == res.Suite {
				idx = i
				break
			}
		}
		if idx < 0 { // the server picked something we didn't offer
			break
		}
		s := remaining[idx]
		accepted = append(accepted, s)
		remaining = append(remaining[:idx:idx], remaining[idx+1:]...)
		sr := SuiteResult{ID: s.ID, Name: s.Name, Grade: s.Grade().String(), FS: s.FS(), DHBits: res.DHBits}
		slot.res.Suites = append(slot.res.Suites, sr)
		if len(slot.certs) == 0 && len(res.Certs) > 0 {
			slot.certs = res.Certs
		}
		if res.HRR {
			break
		}
	}
	slot.res.Supported = len(accepted) > 0

	if len(accepted) >= 2 {
		a, b := accepted[0], accepted[1]
		r1, e1 := probeFn([]probe.Suite{a, b})
		r2, e2 := probeFn([]probe.Suite{b, a})
		if e1 == nil && e2 == nil && r1.Supported && r2.Supported {
			v := r1.Suite == r2.Suite
			slot.res.ServerPrefer = &v
		}
	}
	return slot
}

// fetchCert obtains the certificate with crypto/tls when manual probing
// didn't see it (e.g. TLS-1.3-only servers, which encrypt the certificate).
func fetchCert(addr, sni string, timeout time.Duration) [][]byte {
	d := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(sni) == nil {
		cfg.ServerName = sni
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()
	var out [][]byte
	for _, c := range conn.ConnectionState().PeerCertificates {
		out = append(out, c.Raw)
	}
	return out
}
