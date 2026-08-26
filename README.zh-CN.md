# linux-sg2002-cryptodma

[English](README.md) | 简体中文

为 SG2002 提供低开销 GHASH，以及 OneKVM AES-GCM 用户态 TX offload 的树外
内核模块。

源码按内核系列放在 `5.10/`、`5.15/` 和 `6.18/`。5.15 **不能**软链到 5.10：
5.10 仍用公开的 cipher API 和 `<asm/unaligned.h>`，batch 走
`cvitek_spacc_aes_ctr_encrypt_sg`，并在 SPACC 未就绪时注册 platform 设备；
5.15 需要 `crypto/internal/cipher.h` 以及标识符形式的
`MODULE_IMPORT_NS(CRYPTO_INTERNAL)`，batch keystream 可以走
`cvitek_spacc_aes_ecb_encrypt`；6.18 改用 `<linux/unaligned.h>`、
`noop_llseek`、字符串形式的 namespace import，batch 与 5.10 一样走 CTR。

AES-GCM 由本仓库的 offload 模块注册，不放进 `cvitek-spacc`。
`/dev/onekvm-crypto-offload` 的 ioctl ABI 在三棵树上保持一致。C906L GHASH
共享内存（`0x8FFE0000`）就绪时，batch tag 可以交给 C906L，否则回退到 Linux
GHASH。

## 编译

产物：

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

目标内核必须导出 `cvitek_spacc_kernel_api_ready` 和
`cvitek_spacc_aes_ctr_encrypt_sg`。5.15 的 batch keystream 还使用
`cvitek_spacc_aes_ecb_encrypt`。

## 许可证

GPL-2.0-only，详见 `5.10/`、`5.15/` 或 `6.18/` 源文件中的 SPDX 标识。
