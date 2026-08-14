# BitBox protobuf messages

The top-level `.proto` files are unmodified copies from
[`bitbox02-api-go`](https://github.com/BitBoxSwiss/bitbox02-api-go) commit
`a62f9fddb79d00ae85083be06609280e35138b19`. The bundled
`google/protobuf/empty.proto` comes from protoc 3.21.12.

The checked-in `.pb.c` and `.pb.h` files were generated with protoc 3.21.12
and nanopb 0.4.9.1 at commit
`cad3c18ef15a663e30e3e43e3a752b66378adec1`.

## Regenerate

From the libnunchuk repository root:

```sh
NANOPB_DIR=/absolute/path/to/nanopb
cd src/utils/bitbox/messages
protoc \
  --experimental_allow_proto3_optional \
  --proto_path=. \
  --plugin=protoc-gen-nanopb="$NANOPB_DIR/generator/protoc-gen-nanopb" \
  --nanopb_out=. \
  *.proto google/protobuf/empty.proto
```

The six `.options` files give nanopb fixed bounds for the cryptographic,
backup, device-info, Bitcoin, xpub, and error fields used directly by
`protobuf.cpp`. They affect only the generated C representation, not the wire
format. Removing them requires replacing the direct field access with nanopb
callbacks or allocated fields.

Generated files are committed; downstream builds do not require protoc or the
nanopb generator.
