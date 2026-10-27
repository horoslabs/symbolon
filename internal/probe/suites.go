package probe

// Grade clasifica una suite de cifrado.
type Grade int

const (
	Good     Grade = iota // AEAD con forward secrecy (o TLS 1.3)
	Legacy                // CBC o sin forward secrecy
	Weak                  // 3DES (SWEET32)
	Insecure              // NULL, anónimas, export, RC4, DES
)

func (g Grade) String() string {
	switch g {
	case Good:
		return "good"
	case Legacy:
		return "legacy"
	case Weak:
		return "weak"
	default:
		return "insecure"
	}
}

// Suite describe una suite de cifrado IANA.
type Suite struct {
	ID   uint16
	Name string
	Kex  string // ECDHE, DHE, RSA, ANON, TLS13
	Enc  string // AES128, AES256, CHACHA20, 3DES, RC4, DES, NULL, EXPORT
	Mode string // GCM, CCM, POLY1305, CBC, STREAM, NULL
}

// FS indica si la suite ofrece forward secrecy.
func (s Suite) FS() bool { return s.Kex == "ECDHE" || s.Kex == "DHE" || s.Kex == "TLS13" }

// Grade calcula la nota de la suite.
func (s Suite) Grade() Grade {
	switch {
	case s.Kex == "ANON" || s.Enc == "NULL" || s.Enc == "EXPORT" || s.Enc == "RC4" || s.Enc == "DES":
		return Insecure
	case s.Enc == "3DES":
		return Weak
	case (s.Mode == "GCM" || s.Mode == "POLY1305" || s.Mode == "CCM") && s.FS():
		return Good
	default:
		return Legacy
	}
}

// TLS13Suites son las únicas suites de TLS 1.3.
var TLS13Suites = []Suite{
	{0x1301, "TLS_AES_128_GCM_SHA256", "TLS13", "AES128", "GCM"},
	{0x1302, "TLS_AES_256_GCM_SHA384", "TLS13", "AES256", "GCM"},
	{0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS13", "CHACHA20", "POLY1305"},
}

// LegacySuites son las suites de SSLv3 a TLS 1.2 que se ofrecen al sondear.
var LegacySuites = []Suite{
	{0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "AES128", "GCM"},
	{0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "AES256", "GCM"},
	{0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "AES128", "GCM"},
	{0xC030, "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "AES256", "GCM"},
	{0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE", "CHACHA20", "POLY1305"},
	{0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE", "CHACHA20", "POLY1305"},
	{0x009E, "DHE-RSA-AES128-GCM-SHA256", "DHE", "AES128", "GCM"},
	{0x009F, "DHE-RSA-AES256-GCM-SHA384", "DHE", "AES256", "GCM"},
	{0xCCAA, "DHE-RSA-CHACHA20-POLY1305", "DHE", "CHACHA20", "POLY1305"},
	{0xC023, "ECDHE-ECDSA-AES128-SHA256", "ECDHE", "AES128", "CBC"},
	{0xC024, "ECDHE-ECDSA-AES256-SHA384", "ECDHE", "AES256", "CBC"},
	{0xC027, "ECDHE-RSA-AES128-SHA256", "ECDHE", "AES128", "CBC"},
	{0xC028, "ECDHE-RSA-AES256-SHA384", "ECDHE", "AES256", "CBC"},
	{0xC009, "ECDHE-ECDSA-AES128-SHA", "ECDHE", "AES128", "CBC"},
	{0xC00A, "ECDHE-ECDSA-AES256-SHA", "ECDHE", "AES256", "CBC"},
	{0xC013, "ECDHE-RSA-AES128-SHA", "ECDHE", "AES128", "CBC"},
	{0xC014, "ECDHE-RSA-AES256-SHA", "ECDHE", "AES256", "CBC"},
	{0x0067, "DHE-RSA-AES128-SHA256", "DHE", "AES128", "CBC"},
	{0x006B, "DHE-RSA-AES256-SHA256", "DHE", "AES256", "CBC"},
	{0x0033, "DHE-RSA-AES128-SHA", "DHE", "AES128", "CBC"},
	{0x0039, "DHE-RSA-AES256-SHA", "DHE", "AES256", "CBC"},
	{0x009C, "AES128-GCM-SHA256", "RSA", "AES128", "GCM"},
	{0x009D, "AES256-GCM-SHA384", "RSA", "AES256", "GCM"},
	{0x003C, "AES128-SHA256", "RSA", "AES128", "CBC"},
	{0x003D, "AES256-SHA256", "RSA", "AES256", "CBC"},
	{0x002F, "AES128-SHA", "RSA", "AES128", "CBC"},
	{0x0035, "AES256-SHA", "RSA", "AES256", "CBC"},
	{0xC012, "ECDHE-RSA-DES-CBC3-SHA", "ECDHE", "3DES", "CBC"},
	{0xC008, "ECDHE-ECDSA-DES-CBC3-SHA", "ECDHE", "3DES", "CBC"},
	{0x0016, "DHE-RSA-DES-CBC3-SHA", "DHE", "3DES", "CBC"},
	{0x000A, "DES-CBC3-SHA", "RSA", "3DES", "CBC"},
	{0xC011, "ECDHE-RSA-RC4-SHA", "ECDHE", "RC4", "STREAM"},
	{0xC007, "ECDHE-ECDSA-RC4-SHA", "ECDHE", "RC4", "STREAM"},
	{0x0005, "RC4-SHA", "RSA", "RC4", "STREAM"},
	{0x0004, "RC4-MD5", "RSA", "RC4", "STREAM"},
	{0x0009, "DES-CBC-SHA", "RSA", "DES", "CBC"},
	{0x0015, "DHE-RSA-DES-CBC-SHA", "DHE", "DES", "CBC"},
	{0x0003, "EXP-RC4-MD5", "RSA", "EXPORT", "STREAM"},
	{0x0006, "EXP-RC2-CBC-MD5", "RSA", "EXPORT", "CBC"},
	{0x0008, "EXP-DES-CBC-SHA", "RSA", "EXPORT", "CBC"},
	{0x0014, "EXP-EDH-RSA-DES-CBC-SHA", "DHE", "EXPORT", "CBC"},
	{0x0001, "NULL-MD5", "RSA", "NULL", "NULL"},
	{0x0002, "NULL-SHA", "RSA", "NULL", "NULL"},
	{0x003B, "NULL-SHA256", "RSA", "NULL", "NULL"},
	{0xC006, "ECDHE-ECDSA-NULL-SHA", "ECDHE", "NULL", "NULL"},
	{0xC010, "ECDHE-RSA-NULL-SHA", "ECDHE", "NULL", "NULL"},
	{0x0018, "ADH-RC4-MD5", "ANON", "RC4", "STREAM"},
	{0x001B, "ADH-DES-CBC3-SHA", "ANON", "3DES", "CBC"},
	{0x0034, "ADH-AES128-SHA", "ANON", "AES128", "CBC"},
	{0x003A, "ADH-AES256-SHA", "ANON", "AES256", "CBC"},
	{0x006C, "ADH-AES128-SHA256", "ANON", "AES128", "CBC"},
	{0x006D, "ADH-AES256-SHA256", "ANON", "AES256", "CBC"},
	{0x00A6, "ADH-AES128-GCM-SHA256", "ANON", "AES128", "GCM"},
	{0x00A7, "ADH-AES256-GCM-SHA384", "ANON", "AES256", "GCM"},
	{0xC018, "AECDH-AES128-SHA", "ANON", "AES128", "CBC"},
	{0xC019, "AECDH-AES256-SHA", "ANON", "AES256", "CBC"},
}

var byID = func() map[uint16]Suite {
	m := map[uint16]Suite{}
	for _, s := range LegacySuites {
		m[s.ID] = s
	}
	for _, s := range TLS13Suites {
		m[s.ID] = s
	}
	return m
}()

// Lookup devuelve la suite por ID; si no se conoce, una genérica.
func Lookup(id uint16) Suite {
	if s, ok := byID[id]; ok {
		return s
	}
	return Suite{ID: id, Name: "UNKNOWN", Kex: "?", Enc: "?", Mode: "?"}
}
