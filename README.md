# symbolon

TLS/SSL audit in a single Go binary, no dependencies: protocols, cipher suites with their preference order, certificate, and findings with severity and remediation.

Part of [Horos Labs](https://horoslabs.com).

## How it works

Go's `crypto/tls` isn't suited for auditing (it doesn't support SSLv3 or weak suites, and it won't let you control the ClientHello). Symbolon opens a TCP socket, sends a **hand-built ClientHello**, and reads only the response (ServerHello or alert). It doesn't complete the handshake, so it isn't limited by what Go supports.

- **Protocols:** one ClientHello per version (SSLv3, TLS 1.0, 1.1, 1.2, and 1.3).
- **Suites:** the full list is offered, the server picks one, it's removed, and the process repeats. The resulting order is the server's preference order.
- **Server preference:** two suites are offered in both orders; if it picks the same one, it enforces its own order.
- **TLS 1.3:** `supported_versions` and a fake x25519 `key_share` (only the ServerHello is read).
- **Certificate:** parsed from the same flight (SSLv3 to TLS 1.2); on TLS-1.3-only servers, `crypto/tls` is used as a fallback.
- **Diffie-Hellman:** prime size in DHE suites (Logjam).

## Usage

```bash
go build -o symbolon ./cmd/symbolon

./symbolon scan example.com
./symbolon scan mail.example.com:993 -sni mail.example.com
./symbolon scan -list targets.txt -c 8 -json > tls.json
./symbolon scan -list targets.txt -html > report.html
./symbolon scan -fail-on high example.com   # exit code 2 if findings >= high
```

### HTML report

`-html` writes a single self-contained page with every target: a summary table (worst severity, findings per severity, certificate days left) and, per target, findings with remediation, protocols, suites in preference order and the certificate. It has inline CSS only, no JavaScript or external resources, and a restrictive CSP; every value from the scanned server is escaped. `-html` and `-json` are mutually exclusive.

## Makefile

```bash
make help                  # list of targets
make build                 # build ./symbolon
make test                  # run tests
make check                 # gofmt + go vet + tests
make cover                 # coverage in out/coverage.out
make run TARGET=badssl.com # build and scan
make clean                 # remove artifacts
```

## Findings

Obsolete protocols (SSLv3, TLS 1.0/1.1), NULL/anonymous/export/RC4/DES/3DES suites, lack of forward secrecy, weak DH, suite order enforced by the client, expired or soon-to-expire certificate, mismatched name, untrusted or self-signed chain, weak key or signature.

## Testing against badssl.com

```bash
./symbolon scan expired.badssl.com wrong.host.badssl.com self-signed.badssl.com \
  untrusted-root.badssl.com rc4.badssl.com 3des.badssl.com null.badssl.com \
  dh1024.badssl.com dh512.badssl.com tls-v1-0.badssl.com:1010 tls-v1-1.badssl.com:1011
```

Expected results: `expired` → expired certificate; `wrong.host` → mismatched name; `self-signed` and `untrusted-root` → untrusted chain; `rc4`, `3des`, `null` → corresponding suites; `dh1024`/`dh512` → weak DH; `tls-v1-0`/`tls-v1-1` → obsolete protocol.

## Tests

```bash
go test ./...   # or: make test
```

The tests spin up local TLS servers (one legacy with RC4/3DES, another modern) and check protocols, suites, findings, and certificates.

## Roadmap

- STARTTLS (SMTP, IMAP, POP3, FTP, Postgres).
- Diff between scans.
- Input from the [skopos](https://github.com/horoslabs/skopos) inventory.
- SSLv2, Heartbleed, ROBOT, secure renegotiation, compression, OCSP stapling, and HSTS.
