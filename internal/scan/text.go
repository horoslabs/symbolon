package scan

import (
	"fmt"
	"io"
	"strings"
)

// WriteText imprime el informe en texto plano, corto y apto para móvil.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "== %s ==\n", r.Target)

	fmt.Fprintln(w, "\nProtocolos")
	for _, p := range r.Protocols {
		mark := "no"
		if p.Supported {
			mark = "SÍ"
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
				pref = " (orden del servidor)"
			} else {
				pref = " (orden del cliente)"
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
		fmt.Fprintln(w, "\nCertificado")
		fmt.Fprintf(w, "  Sujeto:  %s\n", c.Subject)
		fmt.Fprintf(w, "  Emisor:  %s\n", c.Issuer)
		fmt.Fprintf(w, "  Validez: %s → %s (%d días)\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), c.DaysLeft)
		fmt.Fprintf(w, "  Clave:   %s %d · firma %s\n", c.KeyType, c.KeyBits, c.SigAlg)
		fmt.Fprintf(w, "  Cadena:  %d certs · confiable: %s · nombre: %s\n", c.ChainLen, yn(c.Trusted), yn(c.HostnameOK))
	}

	fmt.Fprintln(w, "\nHallazgos")
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  ninguno")
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
		fmt.Fprintf(w, "\nnota: %s\n", n)
	}
}

func yn(b bool) string {
	if b {
		return "sí"
	}
	return "NO"
}
