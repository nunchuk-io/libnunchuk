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
    # MSVC limits each string literal to about 16 KB. Split on UTF-8 character
    # boundaries and count bytes, including non-ASCII certificate comments.
    chunks = []
    chunk = []
    chunk_size = 0
    for char in "\n" + pem:
        size = len(char.encode("utf-8"))
        if chunk_size + size > 15000:
            chunks.append("".join(chunk))
            chunk = []
            chunk_size = 0
        chunk.append(char)
        chunk_size += size
    if chunk:
        chunks.append("".join(chunk))
    literals = [f'R"NUNCHUK_CACERT({chunk})NUNCHUK_CACERT"' for chunk in chunks]
    (directory / "cacert_data.cpp").write_text(
        "/* Auto-generated from cacert.pem by generate_cacert.py.\n"
        " * Source: https://curl.se/ca/cacert.pem (Mozilla CA bundle).\n"
        " * Split into adjacent string literals for MSVC C2026.\n"
        " */\n"
        '#include "cacert_data.h"\n\n'
        "namespace nunchuk {\n\n"
        "const char kEmbeddedCaCertificates[] =\n  "
        + "\n  ".join(literals)
        + ";\n\n}  // namespace nunchuk\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
