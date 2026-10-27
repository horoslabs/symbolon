package scan

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/horoslabs/symbolon/internal/probe"
)

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "symbolon.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve levanta un servidor TLS local y devuelve su dirección.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func() {
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func suiteIDs(p *ProtocolResult) map[uint16]bool {
	m := map[uint16]bool{}
	for _, s := range p.Suites {
		m[s.ID] = true
	}
	return m
}

func hasFinding(r *Report, sev, title string) bool {
	for _, f := range r.Findings {
		if f.Severity == sev && f.Title == title {
			return true
		}
	}
	return false
}

func TestScanLegacyServer(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(365*24*time.Hour))
	addr := serve(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{0xC02F, 0xC013, 0xC011, 0x000A},
	})

	r, err := Scan(addr, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	want := map[uint16]bool{
		probe.VersionSSL30: false,
		probe.VersionTLS10: true,
		probe.VersionTLS11: true,
		probe.VersionTLS12: true,
		probe.VersionTLS13: false,
	}
	for v, ok := range want {
		if got := supported(r, v); got != ok {
			t.Errorf("%s soportado = %v, quería %v", probe.VersionName(v), got, ok)
		}
	}

	tls12 := suiteIDs(proto(r, probe.VersionTLS12))
	for _, id := range []uint16{0xC02F, 0xC013, 0xC011, 0x000A} {
		if !tls12[id] {
			t.Errorf("TLS 1.2: falta la suite 0x%04x (aceptadas: %v)", id, tls12)
		}
	}
	if len(tls12) != 4 {
		t.Errorf("TLS 1.2: %d suites, quería 4: %v", len(tls12), tls12)
	}
	// En TLS 1.0 no existen suites AEAD.
	tls10 := suiteIDs(proto(r, probe.VersionTLS10))
	if tls10[0xC02F] || len(tls10) != 3 {
		t.Errorf("TLS 1.0: suites inesperadas %v", tls10)
	}

	for _, f := range []struct{ sev, title string }{
		{High, "Suites RC4 o DES aceptadas"},
		{Medium, "3DES aceptado (SWEET32)"},
		{Medium, "TLS 1.0 habilitado"},
		{Medium, "TLS 1.1 habilitado"},
		{High, "Certificado autofirmado"},
		{Info, "TLS 1.3 no soportado"},
	} {
		if !hasFinding(r, f.sev, f.title) {
			t.Errorf("falta el hallazgo [%s] %s", f.sev, f.title)
		}
	}
	if hasFinding(r, High, "SSLv3 habilitado") {
		t.Error("SSLv3 no debería detectarse")
	}
	if r.Cert == nil || r.Cert.KeyBits != 2048 || !r.Cert.HostnameOK {
		t.Errorf("certificado inesperado: %+v", r.Cert)
	}
	// Los hallazgos van ordenados de más a menos grave.
	for i := 1; i < len(r.Findings); i++ {
		if Rank(r.Findings[i-1].Severity) > Rank(r.Findings[i].Severity) {
			t.Errorf("hallazgos desordenados en %d: %v", i, r.Findings)
		}
	}
}

func TestScanModernServer(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(365*24*time.Hour))
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{cert}})

	r, err := Scan(addr, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if supported(r, probe.VersionTLS10) || supported(r, probe.VersionTLS11) || supported(r, probe.VersionSSL30) {
		t.Error("el servidor moderno no debería aceptar protocolos antiguos")
	}
	if !supported(r, probe.VersionTLS12) || !supported(r, probe.VersionTLS13) {
		t.Fatalf("faltan TLS 1.2/1.3: %+v", r.Protocols)
	}
	if n := len(proto(r, probe.VersionTLS13).Suites); n != 3 {
		t.Errorf("TLS 1.3: %d suites, quería 3", n)
	}
	for _, f := range r.Findings {
		if f.Severity == Critical {
			t.Errorf("hallazgo crítico inesperado: %+v", f)
		}
	}
	if hasFinding(r, Medium, "TLS 1.0 habilitado") || hasFinding(r, Info, "TLS 1.3 no soportado") {
		t.Error("hallazgos de protocolo incorrectos para un servidor moderno")
	}
}

func TestScanExpiredAndHostname(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(-24*time.Hour))
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	_, port, _ := net.SplitHostPort(addr)

	// "localhost" no está en el SAN (solo 127.0.0.1).
	r, err := Scan("localhost:"+port, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(r, High, "Certificado caducado") {
		t.Error("falta el hallazgo de certificado caducado")
	}
	if !hasFinding(r, High, "El certificado no coincide con el nombre") {
		t.Error("falta el hallazgo de nombre no coincidente")
	}
}

func TestSSLv3AlertIsHandled(t *testing.T) {
	cert := selfSigned(t, time.Now().Add(24*time.Hour))
	addr := serve(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	p := &probe.Prober{Addr: addr, Timeout: 3 * time.Second}
	res, err := p.Legacy(probe.VersionSSL30, probe.LegacySuites)
	if err != nil {
		t.Fatal(err)
	}
	if res.Supported || res.Alert != 70 { // 70 = protocol_version
		t.Errorf("esperaba alerta protocol_version, obtuve %+v", res)
	}
}

func TestScanNoTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); c.Close() }()
		}
	}()
	r, err := Scan(ln.Addr().String(), Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Protocols {
		if p.Supported {
			t.Errorf("%s no debería estar soportado en un servicio que no habla TLS", p.Name)
		}
	}
}

func TestScanClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := Scan("127.0.0.1:"+strconv.Itoa(port), Options{Timeout: time.Second}); err == nil {
		t.Error("un puerto cerrado debería dar error")
	}
}

func TestSplitTarget(t *testing.T) {
	for in, want := range map[string][2]string{
		"example.com":      {"example.com", "443"},
		"example.com:8443": {"example.com", "8443"},
		"[::1]:993":        {"::1", "993"},
	} {
		h, p := SplitTarget(in)
		if h != want[0] || strconv.Itoa(p) != want[1] {
			t.Errorf("SplitTarget(%q) = %s,%d", in, h, p)
		}
	}
}
