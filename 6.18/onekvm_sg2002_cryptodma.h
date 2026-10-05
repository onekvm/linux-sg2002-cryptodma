/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ONEKVM_SG2002_CRYPTODMA_H
#define _ONEKVM_SG2002_CRYPTODMA_H

#include <crypto/aes.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

bool cvitek_spacc_kernel_api_ready(void);
int cvitek_spacc_aes_ctr_encrypt_sg(struct scatterlist *source,
	struct scatterlist *destination, unsigned int length, const u8 *key,
	unsigned int key_len, const u8 *iv);
int cvitek_spacc_aes_ctr_encrypt_phys(phys_addr_t buf, unsigned int length,
	const u8 *key, unsigned int key_len, const u8 *iv);

#define CVITEK_SPACC_MAX_CHAIN 32

struct cvitek_spacc_ctr_job {
	void *buf;
	unsigned int length;
	const u8 *iv;
};

int cvitek_spacc_aes_ctr_encrypt_many(struct cvitek_spacc_ctr_job *jobs,
	unsigned int count, const u8 *key, unsigned int key_len);

#endif /* _ONEKVM_SG2002_CRYPTODMA_H */
