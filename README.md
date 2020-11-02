# Nunchuk

## Instruction

On linux, you will need to install udev rules for the devices to be reachable by [HWI](https://github.com/bitcoin-core/HWI). Run `install_udev_script.sh` before using **nunchuk** for the first time, the script will need sudo permission:

```sh
$ sudo ./install_udev_script.sh
```

Or you can run these commands by yourself:

```sh
$ sudo cp udev/*.rules /etc/udev/rules.d/
$ sudo udevadm trigger
$ sudo udevadm control --reload-rules
$ sudo groupadd plugdev
$ sudo usermod -aG plugdev `whoami`
```

Visit [here](https://github.com/bitcoin-core/HWI/tree/master/hwilib/udev) for more details.
