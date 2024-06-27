[![Nunchuk Logo](https://nunchuk.io/wp-content/uploads/2021/03/Horizontal-Logo-2.png)](https://nunchuk.io)

## About
`libnunchuk` is a lean & cross-platform C++ multisig library powered by Bitcoin Core.

`libnunchuk` is used by [the Nunchuk Desktop and Mobile applications](https://nunchuk.io/#Download).

## Why Bitcoin Core

Why does libnunchuk reuse [Bitcoin Core](https://github.com/bitcoin/bitcoin) code?

* Bitcoin Core is the unofficial spec of the Bitcoin protocol.
* Bitcoin Core is the most peer-reviewed and battle-tested in all of Bitcoin.
* Bitcoin Core has important protocol upgrades coming, such as Schnorr signatures and Taproot.

By leveraging Core, libnunchuk can gain access to powerful and reliable Bitcoin tools, while staying lean and cutting down on the number of dependencies.

## Usage

Include `<nunchuk.h>` where you want to use libnunchuk.

```c++
#include <nunchuk.h>

using namespace nunchuk;
```

Create a `Nunchuk` instance.

```c++
// Create an AppSettings object to pass into the Nunchuk instance
AppSettings settings;
settings.set_chain(Chain::TESTNET);
settings.set_hwi_path("bin/hwi");
settings.enable_proxy(false);
settings.set_testnet_servers({"127.0.0.1:50001"});

auto nunchuk = MakeNunchuk(settings);
// ... use nunchuk as you like, see examples below
```

## Examples

Get a list of plugged-in hardware devices.

```c++
auto devices = nunchuk.get()->GetDevices();
```

Create a new signer.

```c++
// ... using the first device returned from above
auto master_signer = nunchuk.get()->CreateMasterSigner(
    "signer_name", devices[0], [](int percent) { 
        // libnunchuk caches xpubs when adding a new master signer, so this method will take some time
        // Use this callback to check on the progress
        return true;
    });
```

Create a new multisig wallet.

```c++
// Nunchuk supports legacy, nested-segwit and native segwit addresses
AddressType address_type = AddressType::NATIVE_SEGWIT;

// Nunchuk supports multisig, singlesig and escrow wallets
WalletType wallet_type = WalletType::MULTI_SIG;

// Get a list of master signers that we manage
auto master_signers = nunchuk.get()->GetMasterSigners();

// Create 2 signers from the first 2 master signers
auto signer0 = nunchuk.get()->GetUnusedSignerFromMasterSigner(
    master_signers[0].get_id(), wallet_type, address_type);
auto signer1 = nunchuk.get()->GetUnusedSignerFromMasterSigner(
    master_signers[1].get_id(), wallet_type, address_type);

// Create a multisig (2/2) wallet
auto wallet = nunchuk.get()->CreateWallet("wallet_name", 2, 2,
    {signer0, signer1}, address_type, false);
```

Convenient util methods are also available in `nunchuk::Utils`.

```c++
auto xpub = Utils::SanitizeBIP32Input(Ypub, "xpub");
auto is_valid = Utils::IsValidXPub(xpub);
auto script_pub_key = Utils::AddressToScriptPubKey(address);
```

For more examples, see [a simple multisig cli less than 300 LOC](examples/main.cpp). 

## Setup

Generally we recommend using libnunchuk as a submodule in a larger CMake project.

```bash
$ cd your_project/
$ git submodule add https://github.com/nunchuk-io/libnunchuk
$ git submodule update --init --recursive
```

Add the following to your `CMakeLists.txt`.

```cmake
add_subdirectory(libnunchuk)
target_link_libraries("${PROJECT_NAME}" PUBLIC nunchuk)
```

Build Bitcoin Core ([details](https://github.com/bitcoin/bitcoin/tree/master/doc#building)).

```
$ pushd libnunchuk/contrib/bitcoin
$ ./autogen.sh
$ ./configure  --disable-shared --enable-wallet --without-gui --disable-zmq --with-miniupnpc=no --without-bdb --disable-bench --disable-tests --disable-fuzz-binary --enable-module-schnorrsig --enable-module-ecdh 
$ make -j8
$ popd
```

Build Sqlcipher ([details](https://github.com/sqlcipher/sqlcipher)).

```
$ pushd libnunchuk/contrib/sqlcipher
$ ./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto"
$ make -j8
$ popd
```

Build your project.

```
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```
## HWI

A [HWI binary](https://github.com/bitcoin-core/HWI/tags) is needed to interact with hardware devices.

Set the HWI path by calling `set_hwi_path()` on `AppSettings`.

## Contributing

Run tests.

```
$ ctest
```

Install `clang-format`.

```
$ brew install clang-format
```

Config `hooks` directory.

```
$ git config core.hooksPath hooks
```

### For VSCode user

Install [clang-format plugins](https://marketplace.visualstudio.com/items?itemName=xaver.clang-format).

Format files using this shortcut: Ctrl+⇧+F on Windows, Ctrl+⇧+I on Linux, and ⇧+⌥+F on macOS.

(Optional) Enable `formatOnSave` in `.vscode/settings.json`.

```json
{
    "editor.formatOnSave": true
}
```

## Nunchuk Applications

The Nunchuk Desktop and Mobile apps are available at https://nunchuk.io.

Read about our design philosophy at:
* [Introducing Nunchuk](https://nunchuk.medium.com/introducing-nunchuk-multisig-made-easy-30d3144d0e09)
* [Introducing libnunchuk](https://nunchuk.medium.com/announcing-libnunchuk-a-lean-cross-platform-multisig-library-powered-by-bitcoin-core-a2f6e26c54df)
* [Bitcoin self-custody: A path forward](https://nunchuk.medium.com/bitcoin-self-custody-a-path-forward-bf131663d19f)

##  License

libnunchuk is released under the terms of the GPLv3 license. See [COPYING](COPYING) for more information or see http://www.gnu.org/licenses/.
