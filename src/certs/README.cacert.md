# Embedded CA certificates for TLS verification (GroupService HTTPS/SSE).
#
# Loaded in-memory into an OpenSSL `X509_STORE` (no temp PEM on disk), so TLS
# verification works with statically-linked OpenSSL on Android/iOS/Windows/
# macOS/Linux where `SSL_CTX_set_default_verify_paths` is often empty.
# Override via `AppSettings::certificate_file` when a custom PEM is needed.
#
# `cacert.pem` is a Mozilla-compatible CA bundle. Update periodically from:
#   https://curl.se/ca/cacert.pem
# then regenerate the embedded C++ blob:
#   python3 -c "
#   from pathlib import Path
#   pem = Path('cacert.pem').read_text()
#   Path('cacert_data.cpp').write_text(
#     '/* Auto-generated from cacert.pem */\\n'
#     '#include \"cacert_data.h\"\\n\\nnamespace nunchuk {\\n\\n'
#     'const char kEmbeddedCaCertificates[] = R\"NUNCHUK_CACERT(\\n'
#     + pem.rstrip() + '\\n)NUNCHUK_CACERT\";\\n\\n}  // namespace nunchuk\\n')
#   "
