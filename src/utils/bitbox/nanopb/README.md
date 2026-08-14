# nanopb runtime

These files are copied from the official
[`nanopb/nanopb`](https://github.com/nanopb/nanopb) repository at tag
`nanopb-0.4.9.1`, commit
`cad3c18ef15a663e30e3e43e3a752b66378adec1`.

Only the runtime required by the checked-in BitBox message bindings is
vendored here: `pb.h`, `pb_common.*`, `pb_decode.*`, and `pb_encode.*`.
`LICENSE.txt` is the corresponding upstream license.

The generator is intentionally not part of libnunchuk and is never invoked by
a client build.
