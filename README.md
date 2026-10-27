# symbolon

Auditoría TLS/SSL en un solo binario de Go, sin dependencias: protocolos, suites con su orden de preferencia, certificado y hallazgos con severidad y remediación.

Parte de [Horos Labs](https://horoslabs.com).

## Cómo funciona

`crypto/tls` de Go no sirve para auditar (no soporta SSLv3 ni suites débiles, y no deja controlar el ClientHello). Symbolon abre un socket TCP, envía un **ClientHello construido a mano** y lee solo la respuesta (ServerHello o alerta). No completa el handshake, así que no depende de lo que Go soporte.

- **Protocolos:** un ClientHello por versión (SSLv3, TLS 1.0, 1.1, 1.2 y 1.3).
- **Suites:** se ofrece la lista completa, el servidor elige una, se retira y se repite. El orden obtenido es el de preferencia del servidor.
- **Preferencia del servidor:** se ofrecen dos suites en ambos órdenes; si elige la misma, impone su orden.
- **TLS 1.3:** `supported_versions` y un `key_share` x25519 falso (solo se lee el ServerHello).
- **Certificado:** se parsea del mismo vuelo (SSLv3 a TLS 1.2); en servidores solo TLS 1.3 se usa `crypto/tls` como alternativa.
- **Diffie-Hellman:** tamaño del primo en suites DHE (Logjam).

## Uso

```bash
go build -o symbolon ./cmd/symbolon

./symbolon scan example.com
./symbolon scan mail.example.com:993 -sni mail.example.com
./symbolon scan -list objetivos.txt -c 8 -json > tls.json
./symbolon scan -fail-on high example.com   # código de salida 2 si hay hallazgos >= high
```

## Hallazgos

Protocolos obsoletos (SSLv3, TLS 1.0/1.1), suites NULL/anónimas/export/RC4/DES/3DES, falta de forward secrecy, DH débil, orden de suites impuesto por el cliente, certificado caducado o próximo a caducar, nombre no coincidente, cadena no confiable o autofirmada, clave o firma débiles.

## Probar contra badssl.com

```bash
./symbolon scan expired.badssl.com wrong.host.badssl.com self-signed.badssl.com \
  untrusted-root.badssl.com rc4.badssl.com 3des.badssl.com null.badssl.com \
  dh1024.badssl.com dh512.badssl.com tls-v1-0.badssl.com:1010 tls-v1-1.badssl.com:1011
```

Resultados esperados: `expired` → certificado caducado; `wrong.host` → nombre no coincidente; `self-signed` y `untrusted-root` → cadena no confiable; `rc4`, `3des`, `null` → suites correspondientes; `dh1024`/`dh512` → DH débil; `tls-v1-0`/`tls-v1-1` → protocolo obsoleto.

## Tests

```bash
go test ./...
```

Los tests levantan servidores TLS locales (uno legacy con RC4/3DES, otro moderno) y comprueban protocolos, suites, hallazgos y certificados.

## Hoja de ruta

- STARTTLS (SMTP, IMAP, POP3, FTP, Postgres).
- Informe HTML y comparación entre escaneos (diff).
- Entrada desde el inventario de [skopos](https://github.com/horoslabs/skopos).
- SSLv2, Heartbleed, ROBOT, renegociación segura, compresión, OCSP stapling y HSTS.
