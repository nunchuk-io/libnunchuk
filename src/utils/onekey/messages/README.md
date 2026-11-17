# OneKey Protocol V1/V2 messages

`onekey.proto` is the Bitcoin/session subset used by this integration. Field
numbers and wire types are taken from:

- OneKeyHQ/firmware-pro `d9ad133c9`, `common/protob/messages-{common,management,bitcoin}.proto`.
- OneKeyHQ/hardware-js-sdk `38f0b8c5`, `packages/core/src/data/messages/messages.json`
  and `messages_legacy_v1.json` (including `BixinPinInputOnDevice`, message 10000).

The `V2*` system-message subset follows `packages/hd-transport/messages-protocol-v2.json`
from hardware-js-sdk `38f0b8c5`. Bitcoin messages keep their existing IDs and wire
fields. Pro 2 is identified by a live V2 Ping response and DeviceInfo hardware
model, then ProtocolInfo capabilities and DeviceStatus are checked before use.
V2 frames are limited to 4200 bytes, including framing and the message type.

Older V2 `ProtocolInfo` responses use capabilities in field 2 and an unused
protobuf definition in field 3; some return only the version. This layout is
recognized by field wire types, following the SDK's compatibility decoder in
`packages/hd-transport/src/protocols/index.ts`. Initialization confirms these
devices with `DeviceStatusGet` instead of requiring an advertised command list.
Current responses still require the build fingerprint and status capability.
Raw PSBT support is enabled only when advertised.

Unused fields are omitted and skipped on decode. The package and message names
are local C symbol names; they do not change the wire format. Numeric script
and request types retain the original enum values. The transaction acknowledgments
use the legacy TxAck envelope, which is wire-compatible with the specialized
TxAckInput/TxAckPrevInput/TxAckOutput/TxAckPrevOutput/TxAckPrevMeta messages.
Only the single requested input/output is encoded in each acknowledgment.

The generated C files use nanopb 0.4.9.3 and the existing runtime under
`utils/bitbox/nanopb`; do not compile a second copy of the runtime. `.options`
bounds keys, fingerprints, signatures and device metadata. Large fields
use callbacks. Path callbacks enforce at most 10 elements and emit unpacked
integers, matching the V1 schema without changing the shared nanopb encoder. Frames and signed PSBTs are bounded by `WireFramer::MAX_MESSAGE_SIZE`.

Regenerate from this directory:

```sh
protoc --proto_path=. \
  --plugin=protoc-gen-nanopb=/path/to/nanopb/generator/protoc-gen-nanopb \
  --nanopb_out=. onekey.proto
```

Generated files are checked in, so clients do not need protoc or nanopb's generator.
