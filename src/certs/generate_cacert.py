#!/usr/bin/env python3
"""Regenerate the embedded C++ bundle after updating cacert.pem."""

from pathlib import Path


def main():
    directory = Path(__file__).resolve().parent
    pem = (directory / "cacert.pem").read_text(encoding="utf-8")
    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise ValueError("cacert.pem contains no certificates")
    if ')NUNCHUK_CACERT"' in pem:
        raise ValueError("cacert.pem contains the C++ raw-string delimiter")
    (directory / "cacert_data.cpp").write_text(
        "/* Auto-generated from cacert.pem by generate_cacert.py.\n"
        " * Source: https://curl.se/ca/cacert.pem (Mozilla CA bundle).\n"
        " */\n"
        '#include "cacert_data.h"\n\n'
        "namespace nunchuk {\n\n"
        'const char kEmbeddedCaCertificates[] = R"NUNCHUK_CACERT(\n'
        + pem.rstrip()
        + '\n)NUNCHUK_CACERT";\n\n}  // namespace nunchuk\n',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
