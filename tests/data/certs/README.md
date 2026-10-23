# TLS regression fixtures

`emudhra-intermediates.pem` contains the 16 public certificates for the eight
compromised eMudhra intermediate keys, including their AAA Certificate Services
cross-signs. Downloaded on 2026-10-22 from:
https://emudhra.we-have-a-problem.com/impacted-intermediates.json

The SPKI SHA-256 hashes were independently recomputed with OpenSSL and checked
against that source. These are public certificates only; no private keys.
