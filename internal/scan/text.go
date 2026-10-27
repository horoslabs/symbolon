package scan

import (
	"fmt"
	"io"
	"strings"
)

// WriteText prints the report as short, mobile-friendly plain text.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "== %s ==\n", r.Target)

	fmt.Fprintln(w, "\nProtocols")
	for _, p := range r.Protocols {
		mark := "no"
		if p.Supported {
			mark = "YES"
		}
		fmt.Fprintf(w, "  %-8s %s\n", p.Name, mark)
	}

	for _, p := range r.Protocols {
		if !p.Supported {
			continue
		}
		pref := ""
		if p.ServerPrefer != nil {
			if *p.ServerPrefer {
				pref = " (server order)"
			} else {
				pref = " (client order)"
			}
		}
		fmt.Fprintf(w, "\n%s: suites%s\n", p.Name, pref)
		for _, s := range p.Suites {
			fs := "  "
			if s.FS {
				fs = "FS"
			}
			dh := ""
			if s.DHBits > 0 {
				dh = fmt.Sprintf(" DH-%d", s.DHBits)
			}
			fmt.Fprintf(w, "  %-8s %s %s%s\n", strings.ToUpper(s.Grade), fs, s.Name, dh)
		}
	}

	if c := r.Cert; c != nil {
		fmt.Fprintln(w, "\nCertificate")
		fmt.Fprintf(w, "  Subject:  %s\n", c.Subject)
		fmt.Fprintf(w, "  Issuer:   %s\n", c.Issuer)
		fmt.Fprintf(w, "  Validity: %s → %s (%d days)\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.DaysLeft)
		fmt.Fprintf(w, "  Key:      %s %d · signature %s\n", c.KeyType, c.KeyBits, c.SigAlg)
		fmt.Fprintf(w, "  Chain:    %d certs · trusted: %s · name: %s\n", c.ChainLen, yn(c.Trusted), yn(c.HostnameOK))
	}

	fmt.Fprintln(w, "\nFindings")
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "      %s\n", f.Detail)
		}
		if f.Fix != "" {
			fmt.Fprintf(w, "      → %s\n", f.Fix)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\nnote: %s\n", n)
	}
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "NO"
}
