// Package probe implements a low-level TLS probe: it builds a ClientHello
// by hand and reads only the server's response. It doesn't complete the
// handshake, so it isn't limited by what crypto/tls supports (SSLv3, weak
// suites, etc.).
package probe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"strings"
	"time"
)

// Protocol versions.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// VersionName returns the human-readable name of a version.
func VersionName(v uint16) string {
	switch v {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// Result is what's learned from a single ClientHello.
type Result struct {
	Supported bool     // the server replied with a ServerHello
	Version   uint16   // negotiated version
	Suite     uint16   // chosen suite
	HRR       bool     // HelloRetryRequest (TLS 1.3)
	Alert     byte     // alert description, if any
	Closed    bool     // the server closed or didn't respond without an alert
	DHBits    int      // DH prime size (DHE suites), 0 if not applicable
	Certs     [][]byte // DER certificate chain (SSLv3 to TLS 1.2)
}

// Prober sends a ClientHello to a server.
type Prober struct {
	Addr    string // host:port
	SNI     string // empty to not send SNI
	Timeout time.Duration
}

var hrrRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func u16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

func ext(typ uint16, data []byte) []byte {
	b := u16(nil, typ)
	b = u16(b, uint16(len(data)))
	return append(b, data...)
}

func (p *Prober) sniExt() []byte {
	if p.SNI == "" || net.ParseIP(p.SNI) != nil {
		return nil
	}
	name := []byte(p.SNI)
	list := append([]byte{0}, u16(nil, uint16(len(name)))...)
	list = append(list, name...)
	return ext(0x0000, append(u16(nil, uint16(len(list))), list...))
}

func groupsExt(groups ...uint16) []byte {
	var g []byte
	for _, x := range groups {
		g = u16(g, x)
	}
	return ext(0x000a, append(u16(nil, uint16(len(g))), g...))
}

func sigAlgsExt() []byte {
	algs := []uint16{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201}
	var a []byte
	for _, x := range algs {
		a = u16(a, x)
	}
	return ext(0x000d, append(u16(nil, uint16(len(a))), a...))
}

func suiteList(suites []Suite) []byte {
	var b []byte
	for _, s := range suites {
		b = u16(b, s.ID)
	}
	return b
}

// wrap wraps the ClientHello body in a handshake message and record.
func wrap(recVer uint16, body []byte) []byte {
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16}
	rec = u16(rec, recVer)
	rec = u16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// LegacyHello builds a ClientHello from SSLv3 to TLS 1.2.
func (p *Prober) LegacyHello(ver uint16, suites []Suite) []byte {
	b := u16(nil, ver)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	b = append(b, 0) // empty session id
	sl := suiteList(suites)
	b = u16(b, uint16(len(sl)))
	b = append(b, sl...)
	b = append(b, 1, 0) // compression: null only

	var exts []byte
	if ver > VersionSSL30 {
		exts = append(exts, p.sniExt()...)
		exts = append(exts, groupsExt(0x001d, 0x0017, 0x0018, 0x0019)...)
		exts = append(exts, ext(0x000b, []byte{1, 0})...)
		if ver >= VersionTLS12 {
			exts = append(exts, sigAlgsExt()...)
		}
		b = u16(b, uint16(len(exts)))
		b = append(b, exts...)
	}
	recVer := ver
	if recVer > VersionTLS10 {
		recVer = VersionTLS10
	}
	return wrap(recVer, b)
}

// TLS13Hello builds a TLS 1.3 ClientHello with a fake x25519 key_share:
// only the ServerHello needs to be read.
func (p *Prober) TLS13Hello(suites []Suite) []byte {
	b := u16(nil, VersionTLS12)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	b = append(b, random...)
	sid := make([]byte, 32)
	_, _ = rand.Read(sid)
	b = append(b, 32)
	b = append(b, sid...)
	sl := suiteList(suites)
	b = u16(b, uint16(len(sl)))
	b = append(b, sl...)
	b = append(b, 1, 0)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	share := u16(nil, 0x001d)
	share = u16(share, 32)
	share = append(share, key...)

	var exts []byte
	exts = append(exts, p.sniExt()...)
	exts = append(exts, groupsExt(0x001d)...)
	exts = append(exts, sigAlgsExt()...)
	exts = append(exts, ext(0x002b, []byte{2, 0x03, 0x04})...)
	exts = append(exts, ext(0x0033, append(u16(nil, uint16(len(share))), share...))...)
	b = u16(b, uint16(len(exts)))
	b = append(b, exts...)
	return wrap(VersionTLS10, b)
}

// Legacy probes a version from SSLv3 to TLS 1.2 offering the given suites.
func (p *Prober) Legacy(ver uint16, suites []Suite) (Result, error) {
	return p.do(p.LegacyHello(ver, suites))
}

// TLS13 probes TLS 1.3 with the given suites.
func (p *Prober) TLS13(suites []Suite) (Result, error) {
	return p.do(p.TLS13Hello(suites))
}

func (p *Prober) do(hello []byte) (Result, error) {
	var res Result
	conn, err := net.DialTimeout("tcp", p.Addr, p.Timeout)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.Timeout))
	if _, err := conn.Write(hello); err != nil {
		res.Closed = true
		return res, nil
	}

	var hs []byte
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if !res.Supported {
				res.Closed = true
			}
			return res, nil
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n > 1<<15 {
			return res, errors.New("TLS record too large: the service doesn't look like TLS")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			if !res.Supported {
				res.Closed = true
			}
			return res, nil
		}
		switch hdr[0] {
		case 0x15: // alert
			if len(body) >= 2 {
				res.Alert = body[1]
			}
			return res, nil
		case 0x16: // handshake
			hs = append(hs, body...)
		default:
			return res, fmt.Errorf("unexpected record type 0x%02x: the service doesn't look like TLS", hdr[0])
		}
		if parseFlight(hs, &res) {
			return res, nil
		}
	}
}

// parseFlight processes the accumulated complete handshake messages and
// returns true once no more reading is needed.
func parseFlight(hs []byte, res *Result) bool {
	for len(hs) >= 4 {
		t := hs[0]
		l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+l {
			return false
		}
		msg := hs[4 : 4+l]
		switch t {
		case 2:
			if !parseServerHello(msg, res) {
				return true
			}
			if res.Version == VersionTLS13 || res.HRR {
				return true
			}
		case 11:
			res.Certs = parseCertificates(msg)
		case 12:
			s := Lookup(res.Suite)
			if (s.Kex == "DHE" || strings.HasPrefix(s.Name, "ADH-")) && len(msg) >= 2 {
				pl := int(msg[0])<<8 | int(msg[1])
				if len(msg) >= 2+pl {
					res.DHBits = bitLen(msg[2 : 2+pl])
				}
			}
		case 14:
			return true
		}
		hs = hs[4+l:]
	}
	return false
}

func parseServerHello(msg []byte, res *Result) bool {
	if len(msg) < 35 {
		return false
	}
	ver := binary.BigEndian.Uint16(msg[0:2])
	random := msg[2:34]
	sidLen := int(msg[34])
	off := 35 + sidLen
	if len(msg) < off+3 {
		return false
	}
	res.Supported = true
	res.Version = ver
	res.Suite = binary.BigEndian.Uint16(msg[off : off+2])
	res.HRR = bytes.Equal(random, hrrRandom)
	off += 3
	if len(msg) >= off+2 {
		el := int(binary.BigEndian.Uint16(msg[off : off+2]))
		off += 2
		end := off + el
		if end > len(msg) {
			end = len(msg)
		}
		for off+4 <= end {
			et := binary.BigEndian.Uint16(msg[off : off+2])
			ed := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
			off += 4
			if off+ed > end {
				break
			}
			if et == 0x002b && ed == 2 {
				res.Version = binary.BigEndian.Uint16(msg[off : off+2])
			}
			off += ed
		}
	}
	return true
}

func parseCertificates(msg []byte) [][]byte {
	if len(msg) < 3 {
		return nil
	}
	total := int(msg[0])<<16 | int(msg[1])<<8 | int(msg[2])
	b := msg[3:]
	if total > len(b) {
		total = len(b)
	}
	b = b[:total]
	var out [][]byte
	for len(b) >= 3 {
		l := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 3+l {
			break
		}
		out = append(out, append([]byte(nil), b[3:3+l]...))
		b = b[3+l:]
	}
	return out
}

func bitLen(b []byte) int {
	for i, x := range b {
		if x != 0 {
			return (len(b)-i-1)*8 + bits.Len8(x)
		}
	}
	return 0
}
