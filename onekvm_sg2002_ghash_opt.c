// SPDX-License-Identifier: GPL-2.0-only
/*
 * Lower-overhead RV64 GHASH implementation for SG2002.
 *
 * The generic implementation uses one 4 KiB multiplication table and shifts
 * the accumulator between all 16 byte lookups.  Precomputing all 32 nibble
 * positions uses only 8 KiB per active key, so the complete keyed table fits
 * in L1 while still avoiding dependent shifts in the hot path.
 */

#include <crypto/algapi.h>
#include <crypto/gf128mul.h>
#include <crypto/ghash.h>
#include <crypto/internal/hash.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define SG2002_GHASH_BYTE_POSITIONS 16
#define SG2002_GHASH_NIBBLE_POSITIONS (SG2002_GHASH_BYTE_POSITIONS * 2)
#define SG2002_GHASH_NIBBLE_VALUES 16

struct sg2002_ghash_ctx {
	be128 table[SG2002_GHASH_NIBBLE_POSITIONS]
		   [SG2002_GHASH_NIBBLE_VALUES];
};

static u16 sg2002_x8_reduction[256];

static void sg2002_gf128mul_x8_lle(be128 *value)
{
	u64 high = be64_to_cpu(value->a);
	u64 low = be64_to_cpu(value->b);
	u64 reduction = sg2002_x8_reduction[low & 0xff];

	value->b = cpu_to_be64((low >> 8) | (high << 56));
	value->a = cpu_to_be64((high >> 8) ^ (reduction << 48));
}

static int sg2002_ghash_init_tfm(struct crypto_tfm *tfm)
{
	return 0;
}

static void sg2002_ghash_exit_tfm(struct crypto_tfm *tfm)
{
	memzero_explicit(crypto_tfm_ctx(tfm),
			 sizeof(struct sg2002_ghash_ctx));
}

static int sg2002_ghash_setkey(struct crypto_shash *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct sg2002_ghash_ctx *ctx = crypto_shash_ctx(tfm);
	struct gf128mul_4k *byte_table;
	be128 positioned_key;
	unsigned int i;
	unsigned int value;

	if (keylen != GHASH_BLOCK_SIZE)
		return -EINVAL;

	memzero_explicit(ctx, sizeof(*ctx));
	memcpy(&positioned_key, key, sizeof(positioned_key));
	for (i = 0; i < SG2002_GHASH_BYTE_POSITIONS; ++i) {
		byte_table = gf128mul_init_4k_lle(&positioned_key);
		if (!byte_table) {
			memzero_explicit(ctx, sizeof(*ctx));
			memzero_explicit(&positioned_key,
					 sizeof(positioned_key));
			return -ENOMEM;
		}
		for (value = 0; value < SG2002_GHASH_NIBBLE_VALUES;
		     ++value) {
			ctx->table[2 * i][value] = byte_table->t[value << 4];
			ctx->table[2 * i + 1][value] = byte_table->t[value];
		}
		gf128mul_free_4k(byte_table);
		sg2002_gf128mul_x8_lle(&positioned_key);
	}
	memzero_explicit(&positioned_key, sizeof(positioned_key));
	return 0;
}

static void sg2002_ghash_multiply(be128 *value,
				  const struct sg2002_ghash_ctx *ctx)
{
	const u8 *bytes = (const u8 *)value;
	be128 result;

	/*
	 * Spell the positions out so GCC keeps both accumulator halves in
	 * registers.  The loop/be128_xor form spills and reloads them for every
	 * nibble on the vendor RV64 toolchain.
	 */
#define SG2002_GHASH_XOR_NIBBLE(position, value) do { \
	result.a ^= ctx->table[(position)][(value)].a; \
	result.b ^= ctx->table[(position)][(value)].b; \
} while (0)
#define SG2002_GHASH_XOR_BYTE(position) do { \
	SG2002_GHASH_XOR_NIBBLE(2 * (position), bytes[(position)] >> 4); \
	SG2002_GHASH_XOR_NIBBLE(2 * (position) + 1, \
				 bytes[(position)] & 0x0f); \
} while (0)
	result.a = 0;
	result.b = 0;
	SG2002_GHASH_XOR_BYTE(0);
	SG2002_GHASH_XOR_BYTE(1);
	SG2002_GHASH_XOR_BYTE(2);
	SG2002_GHASH_XOR_BYTE(3);
	SG2002_GHASH_XOR_BYTE(4);
	SG2002_GHASH_XOR_BYTE(5);
	SG2002_GHASH_XOR_BYTE(6);
	SG2002_GHASH_XOR_BYTE(7);
	SG2002_GHASH_XOR_BYTE(8);
	SG2002_GHASH_XOR_BYTE(9);
	SG2002_GHASH_XOR_BYTE(10);
	SG2002_GHASH_XOR_BYTE(11);
	SG2002_GHASH_XOR_BYTE(12);
	SG2002_GHASH_XOR_BYTE(13);
	SG2002_GHASH_XOR_BYTE(14);
	SG2002_GHASH_XOR_BYTE(15);
#undef SG2002_GHASH_XOR_BYTE
#undef SG2002_GHASH_XOR_NIBBLE
	*value = result;
}

static int sg2002_ghash_init(struct shash_desc *desc)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);

	memset(dctx, 0, sizeof(*dctx));
	return 0;
}

static int sg2002_ghash_update(struct shash_desc *desc, const u8 *src,
			       unsigned int srclen)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct sg2002_ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *dst = dctx->buffer;

	if (dctx->bytes) {
		unsigned int count = min(srclen, dctx->bytes);
		u8 *position = dst + (GHASH_BLOCK_SIZE - dctx->bytes);

		dctx->bytes -= count;
		srclen -= count;
		while (count--)
			*position++ ^= *src++;
		if (!dctx->bytes)
			sg2002_ghash_multiply((be128 *)dst, ctx);
	}

	while (srclen >= GHASH_BLOCK_SIZE) {
		crypto_xor(dst, src, GHASH_BLOCK_SIZE);
		sg2002_ghash_multiply((be128 *)dst, ctx);
		src += GHASH_BLOCK_SIZE;
		srclen -= GHASH_BLOCK_SIZE;
	}

	if (srclen) {
		dctx->bytes = GHASH_BLOCK_SIZE - srclen;
		while (srclen--)
			*dst++ ^= *src++;
	}
	return 0;
}

static int sg2002_ghash_final(struct shash_desc *desc, u8 *output)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct sg2002_ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);

	if (dctx->bytes)
		sg2002_ghash_multiply((be128 *)dctx->buffer, ctx);
	dctx->bytes = 0;
	memcpy(output, dctx->buffer, GHASH_BLOCK_SIZE);
	return 0;
}

#define SG2002_GHASH_ALG(_driver, _priority) { \
	.digestsize = GHASH_DIGEST_SIZE, \
	.init = sg2002_ghash_init, \
	.update = sg2002_ghash_update, \
	.final = sg2002_ghash_final, \
	.setkey = sg2002_ghash_setkey, \
	.descsize = sizeof(struct ghash_desc_ctx), \
	.base = { \
		.cra_name = "ghash", \
		.cra_driver_name = (_driver), \
		.cra_priority = (_priority), \
		.cra_blocksize = GHASH_BLOCK_SIZE, \
		.cra_ctxsize = sizeof(struct sg2002_ghash_ctx), \
		.cra_module = THIS_MODULE, \
		.cra_init = sg2002_ghash_init_tfm, \
		.cra_exit = sg2002_ghash_exit_tfm, \
	}, \
}

static struct shash_alg sg2002_ghash_algorithms[] = {
	SG2002_GHASH_ALG("ghash-sg2002-cryptodma", 300),
};

static int __init sg2002_ghash_module_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sg2002_x8_reduction); ++i) {
		u16 value = 0;

		if (i & 0x80)
			value ^= 0xe100;
		if (i & 0x40)
			value ^= 0x7080;
		if (i & 0x20)
			value ^= 0x3840;
		if (i & 0x10)
			value ^= 0x1c20;
		if (i & 0x08)
			value ^= 0x0e10;
		if (i & 0x04)
			value ^= 0x0708;
		if (i & 0x02)
			value ^= 0x0384;
		if (i & 0x01)
			value ^= 0x01c2;
		sg2002_x8_reduction[i] = value;
	}
	return crypto_register_shashes(sg2002_ghash_algorithms,
				       ARRAY_SIZE(sg2002_ghash_algorithms));
}

static void __exit sg2002_ghash_module_exit(void)
{
	crypto_unregister_shashes(sg2002_ghash_algorithms,
				  ARRAY_SIZE(sg2002_ghash_algorithms));
}

module_init(sg2002_ghash_module_init);
module_exit(sg2002_ghash_module_exit);

MODULE_DESCRIPTION("SG2002 RV64 8 KiB positional-nibble-table GHASH");
MODULE_AUTHOR("OneKVM");
MODULE_LICENSE("GPL");
