package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/horoslabs/symbolon/internal/probe"
)

// Severities, from most to least severe.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Info     = "info"
)

var sevRank = map[string]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}

// Rank returns the order of a severity (0 = most severe).
func Rank(sev string) int {
	if r, ok := sevRank[sev]; ok {
		return r
	}
	return len(sevRank)
}

// Finding is a finding with its explanation and remediation.
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

func proto(r *Report, v uint16) *ProtocolResult {
	for i := range r.Protocols {
		if r.Protocols[i].Version == v {
			return &r.Protocols[i]
		}
	}
	return nil
}

func supported(r *Report, v uint16) bool {
	p := proto(r, v)
	return p != nil && p.Supported
}

// Evaluate generates the findings for a report.
func Evaluate(r *Report) []Finding {
	var fs []Finding
	add := func(sev, title, detail, fix string) {
		fs = append(fs, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// Protocols
	if supported(r, probe.VersionSSL30) {
		add(High, "SSLv3 enabled", "SSLv3 is vulnerable to POODLE and is prohibited by RFC 7568.", "Disable SSLv3 on the server.")
	}
	for _, v := range []uint16{probe.VersionTLS10, probe.VersionTLS11} {
		if supported(r, v) {
			add(Medium, probe.VersionName(v)+" enabled", "Obsolete protocol (RFC 8996); no AEAD suites and exposed to CBC attacks.", "Require TLS 1.2 at minimum.")
		}
	}
	has12, has13 := supported(r, probe.VersionTLS12), supported(r, probe.VersionTLS13)
	switch {
	case !has12 && !has13:
		add(High, "No support for TLS 1.2 or TLS 1.3", "", "Enable TLS 1.2 and TLS 1.3.")
	case !has12:
		add(Low, "TLS 1.2 not supported", "Some clients won't be able to connect.", "Enable TLS 1.2 in addition to TLS 1.3.")
	}
	if !has13 {
		add(Info, "TLS 1.3 not supported", "", "Enable TLS 1.3 if the server supports it.")
	}

	// Suites (aggregated across protocols)
	seen := map[uint16]bool{}
	var critical, rc4des, des3, nofs []string
	minDH := 0
	for _, p := range r.Protocols {
		for _, s := range p.Suites {
			if s.DHBits > 0 && (minDH == 0 || s.DHBits < minDH) {
				minDH = s.DHBits
			}
			if seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			st := probe.Lookup(s.ID)
			switch {
			case st.Kex == "ANON" || st.Enc == "NULL" || st.Enc == "EXPORT":
				critical = append(critical, s.Name)
			case st.Enc == "RC4" || st.Enc == "DES":
				rc4des = append(rc4des, s.Name)
			case st.Enc == "3DES":
				des3 = append(des3, s.Name)
			case !st.FS():
				nofs = append(nofs, s.Name)
			}
		}
	}
	if len(critical) > 0 {
		add(Critical, "Suites with no encryption, anonymous, or export-grade", strings.Join(critical, ", "), "Disable these suites (NULL, aNULL, EXPORT).")
	}
	if len(rc4des) > 0 {
		add(High, "RC4 or DES suites accepted", strings.Join(rc4des, ", "), "Disable RC4 and DES.")
	}
	if len(des3) > 0 {
		add(Medium, "3DES accepted (SWEET32)", strings.Join(des3, ", "), "Disable the 3DES suites.")
	}
	if len(nofs) > 0 {
		add(Low, "Suites without forward secrecy", strings.Join(nofs, ", "), "Prioritize ECDHE/DHE suites and remove static RSA key exchange.")
	}
	if minDH > 0 {
		detail := fmt.Sprintf("DH prime of %d bits.", minDH)
		switch {
		case minDH <= 512:
			add(Critical, "Export-grade Diffie-Hellman parameters", detail, "Use DH groups of at least 2048 bits (RFC 7919), or ECDHE only.")
		case minDH < 1024:
			add(High, "Very weak Diffie-Hellman parameters", detail, "Use DH groups of at least 2048 bits (RFC 7919), or ECDHE only.")
		case minDH < 2048:
			add(Medium, "Weak Diffie-Hellman parameters (Logjam)", detail, "Use DH groups of at least 2048 bits (RFC 7919), or ECDHE only.")
		}
	}
	for _, p := range r.Protocols {
		if p.ServerPrefer != nil && !*p.ServerPrefer {
			add(Low, "The server does not enforce its suite order ("+p.Name+")", "The client decides the suite, so a weak client can force a worse one.", "Enable server cipher preference.")
			break
		}
	}

	// Certificate
	if c := r.Cert; c != nil {
		switch {
		case c.Expired:
			add(High, "Certificate expired", fmt.Sprintf("Expired on %s.", c.NotAfter.Format("2006-01-02")), "Renew the certificate.")
		case c.DaysLeft < 15:
			add(Medium, "Certificate expires in less than 15 days", fmt.Sprintf("Expires on %s (%d days).", c.NotAfter.Format("2006-01-02"), c.DaysLeft), "Renew the certificate.")
		case c.DaysLeft < 30:
			add(Low, "Certificate expires in less than 30 days", fmt.Sprintf("Expires on %s (%d days).", c.NotAfter.Format("2006-01-02"), c.DaysLeft), "Schedule the renewal.")
		}
		if !c.HostnameOK {
			add(High, "Certificate does not match the hostname", c.HostnameErr, "Issue a certificate with the correct name in the SAN.")
		}
		if !c.Trusted && !c.Expired {
			title := "Untrusted certificate chain"
			if c.SelfSigned {
				title = "Self-signed certificate"
			}
			add(High, title, c.TrustErr, "Use a certificate from a public CA and send the full intermediate chain.")
		}
		if (c.KeyType == "RSA" && c.KeyBits < 2048) || (c.KeyType == "ECDSA" && c.KeyBits < 256) {
			add(High, fmt.Sprintf("Weak certificate key (%s %d bits)", c.KeyType, c.KeyBits), "", "Generate an RSA key of 2048 bits or more, or ECDSA P-256.")
		}
		up := strings.ToUpper(c.SigAlg)
		if strings.Contains(up, "SHA1") || strings.Contains(up, "MD5") || strings.Contains(up, "MD2") {
			add(High, "Weak certificate signature ("+c.SigAlg+")", "", "Reissue the certificate with SHA-256 or higher.")
		}
	}

	sort.SliceStable(fs, func(i, j int) bool { return Rank(fs[i].Severity) < Rank(fs[j].Severity) })
	return fs
}
