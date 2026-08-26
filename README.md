# linux-sg2002-cryptodma

English | [简体中文](README.zh-CN.md)

Linux kernel modules providing optimized SG2002 GHASH and OneKVM AES-GCM
offload support.

Sources are split by kernel series under `5.10/`, `5.15/`, and `6.18/`.
Linux 5.15 is not a symlink of 5.10: 5.10 still uses the public cipher API
and `<asm/unaligned.h>`, batches CTR through `cvitek_spacc_aes_ctr_encrypt_sg`,
and can register a fallback SPACC platform device. 5.15 uses
`crypto/internal/cipher.h` and `MODULE_IMPORT_NS(CRYPTO_INTERNAL)` (identifier
form), and may batch keystream through `cvitek_spacc_aes_ecb_encrypt`. 6.18
moves unaligned helpers to `<linux/unaligned.h>`, uses `noop_llseek`, imports
the namespace as a string, and batches CTR like 5.10.

AES-GCM is registered by these offload modules, not by `cvitek-spacc`. The
userspace ioctl ABI (`/dev/onekvm-crypto-offload`) is the same across trees.
When the C906L GHASH shared memory at `0x8FFE0000` is ready, batch tags can
be computed there, with Linux GHASH as fallback.

## Build

The build produces:

- `onekvm_sg2002_ghash_opt.ko`
- `onekvm_crypto_offload.ko`

```sh
make -C /path/to/linux \
    M="$PWD/5.10" \
    ARCH=riscv \
    CROSS_COMPILE=riscv64-linux-gnu- \
    modules

make -C /path/to/linux \
    M="$PWD/5.15" \
    ARCH=riscv \
    CROSS_COMPILE=riscv64-linux-gnu- \
    modules

make -C /path/to/linux \
    M="$PWD/6.18" \
    ARCH=riscv \
    CROSS_COMPILE=riscv64-linux-gnu- \
    modules
```

The target kernel must provide `cvitek_spacc_kernel_api_ready` and
`cvitek_spacc_aes_ctr_encrypt_sg`. 5.15 also uses
`cvitek_spacc_aes_ecb_encrypt` for batched keystream generation.

## License

GPL-2.0-only. See the SPDX identifiers in the source files under `5.10/`,
`5.15/`, or `6.18/`.
