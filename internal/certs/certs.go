// Package certs analyzes the certificate chain presented by a server.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"time"
)

// Info summarizes the leaf certificate and the chain's status.
type Info struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	SigAlg     string    `json:"signature_algorithm"`
	KeyType    string    `json:"key_type"`
	KeyBits    int       `json:"key_bits"`
	SelfSigned bool      `json:"self_signed"`
	ChainLen   int       `json:"chain_length"`

	HostnameOK  bool   `json:"hostname_ok"`
	HostnameErr string `json:"hostname_error,omitempty"`
	Trusted     bool   `json:"trusted"`
	TrustErr    string `json:"trust_error,omitempty"`
	Expired     bool   `json:"expired"`
}

// Analyze parses the DER chain and validates it against the system roots.
// host is the name (or IP) the certificate is checked against.
func Analyze(der [][]byte, host string, now time.Time) (*Info, error) {
	if len(der) == 0 {
		return nil, errors.New("the server sent no certificates")
	}
	var chain []*x509.Certificate
	for _, d := range der {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	leaf := chain[0]

	info := &Info{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		DNSNames:  append([]string(nil), leaf.DNSNames...),
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter:  leaf.NotAfter.UTC(),
		DaysLeft:  int(leaf.NotAfter.Sub(now).Hours() / 24),
		SigAlg:    leaf.SignatureAlgorithm.String(),
		SelfSigned: leaf.Subject.String() == leaf.Issuer.String() &&
			leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil,
		ChainLen: len(chain),
		Expired:  now.After(leaf.NotAfter),
	}
	for _, ip := range leaf.IPAddresses {
		info.DNSNames = append(info.DNSNames, ip.String())
	}
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType, info.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType, info.KeyBits = "ECDSA", k.Params().BitSize
	case ed25519.PublicKey:
		info.KeyType, info.KeyBits = "Ed25519", 256
	default:
		info.KeyType = "unknown"
	}

	if err := leaf.VerifyHostname(host); err != nil {
		info.HostnameErr = err.Error()
	} else {
		info.HostnameOK = true
	}

	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: now})
	if err == nil {
		info.Trusted = true
	} else {
		info.TrustErr = classify(err)
	}
	return info, nil
}

func classify(err error) string {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return "untrusted issuer (incomplete chain, self-signed, or unknown CA)"
	case errors.As(err, &ci) && ci.Reason == x509.Expired:
		return "certificate expired or not yet valid"
	}
	msg := err.Error()
	if i := strings.Index(msg, ":"); i > 0 && strings.HasPrefix(msg, "x509") {
		return msg
	}
	return msg
}
