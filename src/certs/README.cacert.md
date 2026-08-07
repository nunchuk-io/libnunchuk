# Embedded CA certificates for TLS verification (GroupService HTTPS/SSE,
# Electrum SSL).
#
# Loaded in-memory into an OpenSSL `X509_STORE` (no temp PEM on disk), so TLS
# verification works with statically-linked OpenSSL on Android/iOS/Windows/
# macOS/Linux where `SSL_CTX_set_default_verify_paths` is often empty.
# Override via `AppSettings::certificate_file` when a custom PEM is needed.
#
# `cacert.pem` is a Mozilla-compatible CA bundle. Update periodically from:
#   https://curl.se/ca/cacert.pem
# then regenerate the embedded C++ blob (chunked for MSVC C2026 ~16KB/literal):
#   python3 <<'PY'
#   from pathlib import Path
#   pem = Path('cacert.pem').read_text()
#   CHUNK = 15000
#   chunks = [pem[i:i+CHUNK] for i in range(0, len(pem), CHUNK)]
#   parts = [f'R"NUNCHUK_CACERT({c})NUNCHUK_CACERT"' for c in chunks]
#   Path('cacert_data.cpp').write_text(
#     '/* Auto-generated from cacert.pem — do not edit by hand.\\n'
#     ' * Source: Mozilla/curl CA bundle (https://curl.se/ca/cacert.pem).\\n'
#     ' * Split into adjacent string literals for MSVC C2026 (max ~16KB/literal).\\n'
#     ' */\\n#include "cacert_data.h"\\n\\nnamespace nunchuk {\\n\\n'
#     'const char kEmbeddedCaCertificates[] =\\n  '
#     + '\\n  '.join(parts) + '\\n;\\n\\n}  // namespace nunchuk\\n')
#   PY
