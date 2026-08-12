# linux-sg2002-cryptodma

Linux kernel modules providing optimized SG2002 GHASH and OneKVM AES-GCM
offload support.

## Build

Build the modules against a configured Linux kernel tree:

```sh
make -C /path/to/linux \
    M="$PWD" \
    ARCH=riscv \
    CROSS_COMPILE=riscv64-linux-gnu- \
    modules
```

The build produces:

- `onekvm_sg2002_ghash_opt.ko`
- `onekvm_crypto_offload.ko`

The modules target the Linux 5.10 kernel used by OneKVM on SG2002-based
NanoKVM devices.

## License

GPL-2.0-only. See the SPDX license identifiers in the source files.
