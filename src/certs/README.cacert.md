# Embedded CA certificates

`cacert.pem` is curl's Mozilla CA bundle. `generate_cacert.py` embeds it in
`cacert_data.cpp`; the library uses the compiled blob, not the PEM on disk.
The certificates are loaded into an OpenSSL `X509_STORE` for GroupService
HTTPS/SSE, Jade HTTP requests, and Electrum TLS. This works with static OpenSSL
on Android/iOS/Windows/macOS/Linux without writing a temporary PEM file.

The HTTP client treats an explicitly supplied certificate store as authoritative
and does not supplement it with system roots. `AppSettings::certificate_file`
remains an explicit CA/pin override where supported; maintain that file separately.

## Current bundle

- Source: https://curl.se/ca/cacert.pem
- Mozilla snapshot: 2026-10-20, 118 certificates.
- File SHA-256: `796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe`.
- Removes emSign ECC Root CA - G3, emSign ECC Root CA - C3, and
  emSign Root CA - C1. emSign Root CA - G1 remains trusted by Mozilla.
- AAA Certificate Services, which cross-signed affected intermediates, is absent.

The October 2026 eMudhra incident compromised eight intermediate keys.
`sslcerts.cpp` rejects their SHA-256 SPKI hashes, covering both their original
certificates and cross-signs. Electrum checks these keys before its existing
fallback for untrusted/private/self-signed certificates; that fallback is not
general server authentication and is otherwise unchanged. Onion connections
continue to rely on Tor authentication.

Incident and public certificate fixtures:
https://emudhra.we-have-a-problem.com/impacted-intermediates.json

## Updating

From this directory, download the bundle and its published checksum over HTTPS:

```sh
curl --fail --show-error --location --proto '=https' --proto-redir '=https' https://curl.se/ca/cacert.pem -o cacert.pem.new
curl --fail --show-error --location --proto '=https' --proto-redir '=https' https://curl.se/ca/cacert.pem.sha256 -o cacert.pem.sha256.new
python3 - <<'PYTHON'
from pathlib import Path
import hashlib
pem = Path('cacert.pem.new').read_bytes()
expected = Path('cacert.pem.sha256.new').read_text().split()[0]
if hashlib.sha256(pem).hexdigest() != expected:
    raise SystemExit('CA bundle checksum mismatch')
Path('cacert.pem').write_bytes(pem)
Path('cacert.pem.new').unlink()
Path('cacert.pem.sha256.new').unlink()
PYTHON
python3 generate_cacert.py
```

Review the certificate changes, update the snapshot information above, and run
`sslcerts_test` before committing both bundle files. Keep the compromised-key
checks: refreshing roots alone does not protect Electrum's untrusted-CA fallback.
