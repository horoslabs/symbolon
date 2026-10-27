package probe

import "testing"

func hsMsg(t byte, body []byte) []byte {
	m := []byte{t, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(m, body...)
}

func TestParseFlightDHE(t *testing.T) {
	// ServerHello: TLS 1.2, suite DHE-RSA-AES128-SHA (0x0033)
	sh := []byte{0x03, 0x03}
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0, 0x00, 0x33, 0)

	// ServerKeyExchange con un primo de 1024 bits (primer byte 0xFF).
	p := make([]byte, 128)
	p[0] = 0xFF
	ske := append([]byte{0x00, 0x80}, p...)
	ske = append(ske, 0x00, 0x01, 0x02) // g = 2

	var hs []byte
	hs = append(hs, hsMsg(2, sh)...)
	hs = append(hs, hsMsg(12, ske)...)

	var res Result
	if parseFlight(hs, &res) {
		t.Fatal("sin ServerHelloDone no debería terminar")
	}
	hs = append(hs, hsMsg(14, nil)...)
	if !parseFlight(hs, &res) {
		t.Fatal("con ServerHelloDone debería terminar")
	}
	if !res.Supported || res.Version != VersionTLS12 || res.Suite != 0x0033 || res.DHBits != 1024 {
		t.Errorf("resultado inesperado: %+v", res)
	}
}

func TestParseCertificates(t *testing.T) {
	c1, c2 := []byte{1, 2, 3}, []byte{4, 5}
	list := []byte{0, 0, 3, 1, 2, 3, 0, 0, 2, 4, 5}
	msg := append([]byte{0, 0, byte(len(list))}, list...)
	got := parseCertificates(msg)
	if len(got) != 2 || string(got[0]) != string(c1) || string(got[1]) != string(c2) {
		t.Errorf("certificados: %v", got)
	}
}

func TestBitLen(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want int
	}{
		{[]byte{0x80}, 8},
		{[]byte{0x00, 0x01}, 1},
		{[]byte{0xFF, 0x00}, 16},
		{nil, 0},
	} {
		if got := bitLen(c.in); got != c.want {
			t.Errorf("bitLen(%v) = %d, quería %d", c.in, got, c.want)
		}
	}
}

func TestSSLv3HelloHasNoExtensions(t *testing.T) {
	p := &Prober{SNI: "example.com"}
	h := p.LegacyHello(VersionSSL30, LegacySuites[:2])
	if h[0] != 0x16 || h[1] != 0x03 || h[2] != 0x00 {
		t.Errorf("cabecera de registro SSLv3 incorrecta: % x", h[:5])
	}
	// 5 (registro) + 4 (handshake) + 2 + 32 + 1 + 2 + 4 + 2 = 52, sin extensiones
	if len(h) != 52 {
		t.Errorf("longitud = %d, quería 52 (sin extensiones)", len(h))
	}
	tls12 := p.LegacyHello(VersionTLS12, LegacySuites[:2])
	if len(tls12) <= len(h) {
		t.Error("el hello de TLS 1.2 debería llevar extensiones")
	}
}

func TestGrades(t *testing.T) {
	for id, want := range map[uint16]Grade{
		0xC02F: Good, 0x1301: Good, 0xC013: Legacy, 0x009C: Legacy,
		0x000A: Weak, 0x0005: Insecure, 0x0001: Insecure, 0x0034: Insecure, 0x0003: Insecure,
	} {
		if got := Lookup(id).Grade(); got != want {
			t.Errorf("0x%04x: %s, quería %s", id, got, want)
		}
	}
}
