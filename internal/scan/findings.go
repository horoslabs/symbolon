package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/horoslabs/symbolon/internal/probe"
)

// Severidades, de mayor a menor.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Info     = "info"
)

var sevRank = map[string]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}

// Rank devuelve el orden de una severidad (0 = más grave).
func Rank(sev string) int {
	if r, ok := sevRank[sev]; ok {
		return r
	}
	return len(sevRank)
}

// Finding es un hallazgo con su explicación y remediación.
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

// Evaluate genera los hallazgos de un informe.
func Evaluate(r *Report) []Finding {
	var fs []Finding
	add := func(sev, title, detail, fix string) {
		fs = append(fs, Finding{Severity: sev, Title: title, Detail: detail, Fix: fix})
	}

	// Protocolos
	if supported(r, probe.VersionSSL30) {
		add(High, "SSLv3 habilitado", "SSLv3 es vulnerable a POODLE y está prohibido por RFC 7568.", "Desactiva SSLv3 en el servidor.")
	}
	for _, v := range []uint16{probe.VersionTLS10, probe.VersionTLS11} {
		if supported(r, v) {
			add(Medium, probe.VersionName(v)+" habilitado", "Protocolo obsoleto (RFC 8996); sin suites AEAD y expuesto a ataques de CBC.", "Exige TLS 1.2 como mínimo.")
		}
	}
	has12, has13 := supported(r, probe.VersionTLS12), supported(r, probe.VersionTLS13)
	switch {
	case !has12 && !has13:
		add(High, "Sin soporte para TLS 1.2 ni TLS 1.3", "", "Habilita TLS 1.2 y TLS 1.3.")
	case !has12:
		add(Low, "TLS 1.2 no soportado", "Algunos clientes no podrán conectar.", "Habilita TLS 1.2 además de TLS 1.3.")
	}
	if !has13 {
		add(Info, "TLS 1.3 no soportado", "", "Habilita TLS 1.3 si el servidor lo permite.")
	}

	// Suites (agregadas entre protocolos)
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
		add(Critical, "Suites sin cifrado, anónimas o de exportación", strings.Join(critical, ", "), "Desactiva estas suites (NULL, aNULL, EXPORT).")
	}
	if len(rc4des) > 0 {
		add(High, "Suites RC4 o DES aceptadas", strings.Join(rc4des, ", "), "Desactiva RC4 y DES.")
	}
	if len(des3) > 0 {
		add(Medium, "3DES aceptado (SWEET32)", strings.Join(des3, ", "), "Desactiva las suites 3DES.")
	}
	if len(nofs) > 0 {
		add(Low, "Suites sin forward secrecy", strings.Join(nofs, ", "), "Prioriza suites ECDHE/DHE y retira el intercambio de claves RSA estático.")
	}
	if minDH > 0 {
		detail := fmt.Sprintf("Primo DH de %d bits.", minDH)
		switch {
		case minDH <= 512:
			add(Critical, "Parámetros Diffie-Hellman de exportación", detail, "Usa grupos DH de al menos 2048 bits (RFC 7919) o solo ECDHE.")
		case minDH < 1024:
			add(High, "Parámetros Diffie-Hellman muy débiles", detail, "Usa grupos DH de al menos 2048 bits (RFC 7919) o solo ECDHE.")
		case minDH < 2048:
			add(Medium, "Parámetros Diffie-Hellman débiles (Logjam)", detail, "Usa grupos DH de al menos 2048 bits (RFC 7919) o solo ECDHE.")
		}
	}
	for _, p := range r.Protocols {
		if p.ServerPrefer != nil && !*p.ServerPrefer {
			add(Low, "El servidor no impone su orden de suites ("+p.Name+")", "El cliente decide la suite, así que un cliente débil puede forzar una suite peor.", "Activa la preferencia de cifrados del servidor.")
			break
		}
	}

	// Certificado
	if c := r.Cert; c != nil {
		switch {
		case c.Expired:
			add(High, "Certificado caducado", fmt.Sprintf("Caducó el %s.", c.NotAfter.Format("2006-01-02")), "Renueva el certificado.")
		case c.DaysLeft < 15:
			add(Medium, "El certificado caduca en menos de 15 días", fmt.Sprintf("Caduca el %s (%d días).", c.NotAfter.Format("2006-01-02"), c.DaysLeft), "Renueva el certificado.")
		case c.DaysLeft < 30:
			add(Low, "El certificado caduca en menos de 30 días", fmt.Sprintf("Caduca el %s (%d días).", c.NotAfter.Format("2006-01-02"), c.DaysLeft), "Programa la renovación.")
		}
		if !c.HostnameOK {
			add(High, "El certificado no coincide con el nombre", c.HostnameErr, "Emite un certificado con el nombre correcto en el SAN.")
		}
		if !c.Trusted && !c.Expired {
			title := "Cadena de certificados no confiable"
			if c.SelfSigned {
				title = "Certificado autofirmado"
			}
			add(High, title, c.TrustErr, "Usa un certificado de una CA pública y envía la cadena intermedia completa.")
		}
		if (c.KeyType == "RSA" && c.KeyBits < 2048) || (c.KeyType == "ECDSA" && c.KeyBits < 256) {
			add(High, fmt.Sprintf("Clave del certificado débil (%s %d bits)", c.KeyType, c.KeyBits), "", "Genera una clave RSA de 2048 bits o más, o ECDSA P-256.")
		}
		up := strings.ToUpper(c.SigAlg)
		if strings.Contains(up, "SHA1") || strings.Contains(up, "MD5") || strings.Contains(up, "MD2") {
			add(High, "Firma del certificado débil ("+c.SigAlg+")", "", "Reemite el certificado con SHA-256 o superior.")
		}
	}

	sort.SliceStable(fs, func(i, j int) bool { return Rank(fs[i].Severity) < Rank(fs[j].Severity) })
	return fs
}
