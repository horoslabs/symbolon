// Package scan orchestrates probing a TLS target: protocols, suites,
// preference order, certificate and findings.
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
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
	// ProbeError says why the version was not negotiated (alert, close,
	// timeout or error). Empty when supported.
	ProbeError string `json:"probe_error,omitempty"`
	// NoAnswer is true when the probe got nothing back at all (closed,
	// timed out or could not connect), as opposed to an alert.
	NoAnswer bool `json:"-"`
}

// Report is the full result for a target.
type Report struct {
	Target    string           `json:"target"`
	Host      string           `json:"host"`
	IP        string           `json:"ip"`
	Port      int              `json:"port"`
	ScannedAt time.Time        `json:"scanned_at"`
	Protocols []ProtocolResult `json:"protocols"`
	Cert      *certs.Info      `json:"certificate,omitempty"`
	Findings  []Finding        `json:"findings"`
	Notes     []string         `json:"notes,omitempty"`
}

// Negotiated reports whether any probe got a ServerHello.
func (r *Report) Negotiated() bool {
	for _, p := range r.Protocols {
		if p.Supported {
			return true
		}
	}
	return false
}

// Unanswered reports whether no probe got any reply from the server, so
// "not supported" cannot be told apart from "not reachable".
func (r *Report) Unanswered() bool {
	if len(r.Protocols) == 0 {
		return false
	}
	for _, p := range r.Protocols {
		if p.Supported || !p.NoAnswer {
			return false
		}
	}
	return true
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

// lookupIP resolves a hostname. Tests replace it to fake DNS.
var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// resolve returns the target's IPs, IPv4 first. An IP literal is returned
// as is.
func resolve(host string, timeout time.Duration) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := lookupIP(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no addresses found", host)
	}
	sort.SliceStable(ips, func(i, j int) bool {
		return ips[i].To4() != nil && ips[j].To4() == nil
	})
	return ips, nil
}

func tcpCheck(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// Scan probes a target (host or host:port). The host is resolved once and
// the first IP that accepts a TCP connection is pinned for every probe, so
// multi-IP hosts give consistent results.
func Scan(target string, opt Options) (*Report, error) {
	opt = withDefaults(opt)
	host, port := SplitTarget(target)
	ips, err := resolve(host, opt.Timeout)
	if err != nil {
		return nil, err
	}
	var fails []string
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		if err := tcpCheck(addr, opt.Timeout); err != nil {
			fails = append(fails, ip.String()+": "+err.Error())
			continue
		}
		return scanIP(target, host, ip.String(), port, opt), nil
	}
	return nil, fmt.Errorf("no reachable address for %s: %s", host, strings.Join(fails, "; "))
}

// ScanAll scans every resolved IP of the target separately. It returns the
// reports for reachable IPs and an error listing the unreachable ones.
func ScanAll(target string, opt Options) ([]*Report, error) {
	opt = withDefaults(opt)
	host, port := SplitTarget(target)
	ips, err := resolve(host, opt.Timeout)
	if err != nil {
		return nil, err
	}
	reports := make([]*Report, len(ips))
	errs := make([]error, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			if err := tcpCheck(addr, opt.Timeout); err != nil {
				errs[i] = fmt.Errorf("%s: %w", ip, err)
				return
			}
			reports[i] = scanIP(target, host, ip, port, opt)
		}(i, ip.String())
	}
	wg.Wait()
	var out []*Report
	for _, r := range reports {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, errors.Join(errs...)
}

func withDefaults(opt Options) Options {
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	return opt
}

// scanIP runs every probe against one pinned IP. SNI stays the hostname.
func scanIP(target, host, ip string, port int, opt Options) *Report {
	sni := opt.SNI
	if sni == "" {
		sni = host
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	p := &probe.Prober{Addr: addr, SNI: sni, Timeout: opt.Timeout}

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
		IP:        ip,
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
		if len(der) > 0 && !r.Negotiated() {
			r.Notes = append(r.Notes, "certificate obtained only through the crypto/tls fallback; every raw probe failed, so something may be filtering hand-built ClientHellos")
		}
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
	return r
}

type versionSlot struct {
	res     ProtocolResult
	certs   [][]byte
	notes   []string
	dhBySID map[uint16]int
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
	for i := range all {
		if len(remaining) == 0 {
			break
		}
		first := i == 0
		res, err := probeFn(remaining)
		if err != nil {
			slot.notes = append(slot.notes, slot.res.Name+": "+err.Error())
			if first {
				slot.res.ProbeError, slot.res.NoAnswer = probeErrReason(err)
			}
			break
		}
		if !res.Supported || res.Version != ver {
			if first {
				slot.res.ProbeError = res.FailReason()
				slot.res.NoAnswer = res.Closed || res.TimedOut
				if res.Supported {
					slot.res.ProbeError = "server replied with " + probe.VersionName(res.Version)
				}
			}
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

// probeErrReason classifies a probe error. Network errors (dial failures,
// timeouts) mean the server never answered; anything else came from a
// reply that was not TLS.
func probeErrReason(err error) (string, bool) {
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return probe.ReasonTimeout, true
		}
		return err.Error(), true
	}
	return err.Error(), false
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
