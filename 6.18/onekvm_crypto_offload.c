// SPDX-License-Identifier: GPL-2.0-only
/* OneKVM low-overhead userspace AES-GCM TX offload ABI. */

#include <crypto/aes.h>
#include <crypto/hash.h>
#include <crypto/internal/cipher.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/crypto.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/ktime.h>
#include <linux/processor.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/mm.h>
#include <linux/wait.h>

#include "onekvm_sg2002_cryptodma.h"
#include "onekvm_ghash_ipc.h"

#define ONEKVM_OFFLOAD_NAME "onekvm-crypto-offload"
#define ONEKVM_OFFLOAD_ABI_VERSION 1
#define ONEKVM_OFFLOAD_IOCTL_TYPE 0xb7
#define ONEKVM_OFFLOAD_GHASH_NAME "ghash-sg2002-cryptodma"
#define ONEKVM_OFFLOAD_AES_NAME "aes-generic"
#define ONEKVM_OFFLOAD_GCM_IV_SIZE 12
#define ONEKVM_OFFLOAD_GCM_TAG_SIZE 16
#define ONEKVM_OFFLOAD_MAX_INPUT (20 * 1024)
#define ONEKVM_OFFLOAD_MAX_BATCH 128
#define ONEKVM_OFFLOAD_BATCH_BUFFER_SIZE (32 * 1024)
#define ONEKVM_OFFLOAD_RTOS_VERIFY_PACKETS 128

static unsigned int offload_rtos_ghash_timeout_ms = 1000;
module_param_named(rtos_ghash_timeout_ms, offload_rtos_ghash_timeout_ms,
		   uint, 0644);
MODULE_PARM_DESC(rtos_ghash_timeout_ms,
		 "C906L GHASH IPC timeout in milliseconds");

static bool offload_use_rtos_ghash = false;
module_param_named(rtos_ghash, offload_use_rtos_ghash, bool, 0644);
MODULE_PARM_DESC(rtos_ghash,
		 "Use C906L GHASH IPC (Y) or Linux ghash-sg2002-cryptodma (N)");

static bool offload_ctr_chain = false;
module_param_named(ctr_chain, offload_ctr_chain, bool, 0644);
MODULE_PARM_DESC(ctr_chain,
		 "Chain CryptoDMA CTR descriptors (one WR_INT poll per batch)");

#define OFFLOAD_GHASH_WAIT_SLEEP 0
#define OFFLOAD_GHASH_WAIT_SPIN 1
#define OFFLOAD_GHASH_WAIT_IRQ 2

static int offload_ghash_wait = OFFLOAD_GHASH_WAIT_IRQ;
module_param_named(ghash_wait, offload_ghash_wait, int, 0644);
MODULE_PARM_DESC(ghash_wait,
		 "C906L GHASH wait: 0=usleep, 1=spin, 2=mailbox IRQ wait_event");

#define OFFLOAD_MBOX_PHYS 0x01900000UL
#define OFFLOAD_MBOX_SIZE 0x1000
#define OFFLOAD_MBOX_EN_CPU1 0x04
#define OFFLOAD_MBOX_CLR_CPU1 0x20
#define OFFLOAD_MBOX_SETINT_CPU1 0x28
#define OFFLOAD_MBOX_CONTEXT 0x400
#define OFFLOAD_MBOX_SLOTS 8

static wait_queue_head_t offload_ghash_wq;
static void __iomem *offload_mbox_base;
static int offload_mbox_irq = -1;
static unsigned long offload_ghash_irq_wakes;
module_param_named(ghash_irq_wakes, offload_ghash_irq_wakes, ulong, 0444);

struct onekvm_offload_key_config {
	__u32 version;
	__u32 key_len;
	__u32 auth_size;
	__u32 reserved;
	__u8 key[32];
};

struct onekvm_offload_encrypt_request {
	__u32 version;
	__u32 flags;
	__u32 aad_len;
	__u32 data_len;
	__aligned_u64 aad_ptr;
	__aligned_u64 src_ptr;
	__aligned_u64 dst_ptr;
	__u8 iv[ONEKVM_OFFLOAD_GCM_IV_SIZE];
	__u8 reserved[4];
};

struct onekvm_offload_batch_request {
	__u32 version;
	__u32 flags;
	__u32 count;
	__u32 completed;
	__aligned_u64 requests_ptr;
};

static_assert(sizeof(struct onekvm_offload_key_config) == 48);
static_assert(sizeof(struct onekvm_offload_encrypt_request) == 56);
static_assert(sizeof(struct onekvm_offload_batch_request) == 24);

#define ONEKVM_OFFLOAD_SET_KEY \
	_IOW(ONEKVM_OFFLOAD_IOCTL_TYPE, 0x01, struct onekvm_offload_key_config)
#define ONEKVM_OFFLOAD_ENCRYPT \
	_IOWR(ONEKVM_OFFLOAD_IOCTL_TYPE, 0x02, struct onekvm_offload_encrypt_request)
#define ONEKVM_OFFLOAD_ENCRYPT_BATCH \
	_IOWR(ONEKVM_OFFLOAD_IOCTL_TYPE, 0x03, struct onekvm_offload_batch_request)

struct onekvm_offload_context {
	struct mutex lock;
	struct crypto_shash *ghash;
	struct shash_desc *ghash_desc;
	struct crypto_cipher *aes;
	u8 *input;
	u8 *batch_data;
	u8 (*batch_tags)[AES_BLOCK_SIZE];
	u8 key[AES_MAX_KEY_SIZE];
	u8 hash_subkey[AES_BLOCK_SIZE];
	unsigned int key_len;
	unsigned int rtos_verify_remaining;
};

static bool onekvm_offload_ranges_overlap(unsigned long first,
					  size_t first_length,
					  unsigned long second,
					  size_t second_length)
{
	return first < second + second_length &&
	       second < first + first_length;
}

static atomic64_t offload_tx_packets = ATOMIC64_INIT(0);
static atomic64_t offload_tx_bytes = ATOMIC64_INIT(0);
static atomic64_t offload_tx_errors = ATOMIC64_INIT(0);
static atomic_t offload_last_error = ATOMIC_INIT(0);
static atomic64_t offload_crypto_ns = ATOMIC64_INIT(0);
static atomic64_t offload_batch_calls = ATOMIC64_INIT(0);
static atomic64_t offload_batch_packets = ATOMIC64_INIT(0);
static atomic64_t offload_batch_unique_pages = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_batches = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_packets = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_bytes = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_ns = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_verified = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_fallbacks = ATOMIC64_INIT(0);
static atomic64_t offload_rtos_ghash_errors = ATOMIC64_INIT(0);
static char offload_driver_name[CRYPTO_MAX_ALG_NAME] = "unconfigured";
static DEFINE_MUTEX(offload_driver_name_lock);
static DEFINE_MUTEX(offload_rtos_ghash_lock);
static void __iomem *offload_rtos_ghash_iomem;
static struct onekvm_ghash_shm __iomem *offload_rtos_ghash_shm;
static void *offload_ghash_cpu;
static bool offload_ghash_cached;
static bool offload_rtos_ghash_enabled;
static u8 *offload_ring_payload_raw[ONEKVM_GHASH_RING_SLOTS];
static u8 *offload_ring_payload[ONEKVM_GHASH_RING_SLOTS];
static phys_addr_t offload_ring_payload_phys[ONEKVM_GHASH_RING_SLOTS];
static u32 offload_ring_seq = 1;

static void onekvm_offload_disable_rtos_ghash(const char *reason)
{
	mutex_lock(&offload_rtos_ghash_lock);
	if (offload_rtos_ghash_enabled) {
		offload_rtos_ghash_enabled = false;
		pr_warn("OneKVM crypto offload: disabling C906L GHASH: %s\n",
			reason);
	}
	mutex_unlock(&offload_rtos_ghash_lock);
}

static irqreturn_t onekvm_offload_mbox_irq(int irq, void *dev)
{
	u8 set;
	unsigned int i;

	if (!offload_mbox_base)
		return IRQ_NONE;
	set = readb(offload_mbox_base + OFFLOAD_MBOX_SETINT_CPU1);
	if (!set)
		return IRQ_NONE;
	for (i = 0; i < OFFLOAD_MBOX_SLOTS; i++) {
		u8 valid = set & BIT(i);

		if (!valid)
			continue;
		writeb(valid, offload_mbox_base + OFFLOAD_MBOX_CLR_CPU1);
		writeb(readb(offload_mbox_base + OFFLOAD_MBOX_EN_CPU1) & ~valid,
		       offload_mbox_base + OFFLOAD_MBOX_EN_CPU1);
		writel(0, offload_mbox_base + OFFLOAD_MBOX_CONTEXT + i * 8);
		writel(0, offload_mbox_base + OFFLOAD_MBOX_CONTEXT + i * 8 + 4);
	}
	offload_ghash_irq_wakes++;
	wake_up(&offload_ghash_wq);
	return IRQ_HANDLED;
}

static u8 *onekvm_offload_slot_payload(unsigned int index)
{
	return offload_ring_payload[index];
}

static int onekvm_offload_wait_slot_state(
	struct onekvm_ghash_slot __iomem *slot, u32 want, u64 deadline_ns)
{
	int mode = READ_ONCE(offload_ghash_wait);

	if (mode == OFFLOAD_GHASH_WAIT_IRQ && offload_mbox_irq >= 0 &&
	    want == ONEKVM_GHASH_SLOT_DONE) {
		long timeout_jiffies = msecs_to_jiffies(
			READ_ONCE(offload_rtos_ghash_timeout_ms));

		if (!wait_event_timeout(offload_ghash_wq,
					readl(&slot->state) == want,
					timeout_jiffies) &&
		    readl(&slot->state) != want)
			return -ETIMEDOUT;
		return 0;
	}
	while (readl(&slot->state) != want) {
		if (ktime_get_ns() >= deadline_ns)
			return -ETIMEDOUT;
		if (mode == OFFLOAD_GHASH_WAIT_SPIN)
			cpu_relax();
		else
			usleep_range(50, 100);
	}
	return 0;
}

static int onekvm_offload_write_gcm_tag(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters,
	const u8 *raw_tag);
static int onekvm_offload_ghash(
	struct onekvm_offload_context *context,
	const u8 *aad, unsigned int aad_len,
	struct scatterlist *ciphertext,
	unsigned int ciphertext_len, u8 *tag);

static int onekvm_offload_harvest_slot(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *requests,
	unsigned int first, unsigned int count,
	u8 *payload, struct onekvm_ghash_slot __iomem *slot,
	unsigned int *completed, bool use_c906l_tags)
{
	unsigned int i;
	int error;

	if (use_c906l_tags) {
		error = (s32)readl(&slot->status);
		if (error)
			return error;
	}
	for (i = 0; i < count; i++) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[first + i];
		void __user *dst_user =
			(void __user *)(uintptr_t)request->dst_ptr;
		u32 data_offset = readl(&slot->requests[i].data_offset);
		u32 aad_offset = readl(&slot->requests[i].aad_offset);
		u8 tag[AES_BLOCK_SIZE];

		if (request->data_len &&
		    copy_to_user(dst_user, payload + data_offset,
				 request->data_len))
			return -EFAULT;
		if (use_c906l_tags) {
			memcpy_fromio(tag, slot->requests[i].tag,
				      AES_BLOCK_SIZE);
		} else {
			struct scatterlist ciphertext;

			if (request->data_len)
				sg_init_one(&ciphertext,
					    payload + data_offset,
					    request->data_len);
			else
				sg_init_table(&ciphertext, 1);
			error = onekvm_offload_ghash(
				context, payload + aad_offset,
				request->aad_len, &ciphertext,
				request->data_len, tag);
			if (error)
				return error;
		}
		error = onekvm_offload_write_gcm_tag(context, request, tag);
		memzero_explicit(tag, sizeof(tag));
		if (error)
			return error;
		(*completed)++;
	}
	if (use_c906l_tags)
		writel(ONEKVM_GHASH_SLOT_EMPTY, &slot->state);
	return 0;
}

static void onekvm_offload_ring_reset(struct onekvm_ghash_shm __iomem *shm)
{
	unsigned int slot;

	for (slot = 0; slot < ONEKVM_GHASH_RING_SLOTS; slot++) {
		writel(ONEKVM_GHASH_SLOT_EMPTY, &shm->slots[slot].state);
		writel(0, &shm->slots[slot].status);
		writel(0, &shm->slots[slot].count);
	}
	writel(0, &shm->prod);
	writel(0, &shm->cons);
	writel(0, &shm->done);
	wmb();
}

static int onekvm_offload_ring_claim(
	struct onekvm_ghash_slot __iomem *slot, u64 deadline_ns)
{
	u32 state = readl(&slot->state);
	int error;

	if (state == ONEKVM_GHASH_SLOT_EMPTY)
		return 0;
	if (state != ONEKVM_GHASH_SLOT_READY &&
	    state != ONEKVM_GHASH_SLOT_DONE)
		goto empty;
	error = onekvm_offload_wait_slot_state(
		slot, ONEKVM_GHASH_SLOT_DONE, deadline_ns);
	if (error)
		return error;
empty:
	writel(ONEKVM_GHASH_SLOT_EMPTY, &slot->state);
	wmb();
	return 0;
}

static int onekvm_offload_ring_publish(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *requests,
	unsigned int first, unsigned int *count_out, unsigned int idx,
	u64 *byte_count)
{
	struct onekvm_ghash_slot __iomem *slot =
		&offload_rtos_ghash_shm->slots[idx];
	u8 *payload = onekvm_offload_slot_payload(idx);
	unsigned int count = 0;
	unsigned int used = 0;
	unsigned int index;
	u32 seq;
	int error;

	if (!payload)
		return -ENODEV;
	while (first + count < *count_out &&
	       count < ONEKVM_GHASH_MAX_REQUESTS) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[first + count];
		unsigned int padded = request->data_len ?
			ALIGN(request->data_len, AES_BLOCK_SIZE) : 0;
		unsigned int data_off =
			ALIGN(used + request->aad_len, AES_BLOCK_SIZE);
		unsigned int need = data_off - used + padded;

		if (used + need > ONEKVM_GHASH_SLOT_PAYLOAD)
			break;
		used += need;
		count++;
	}
	if (!count)
		return -EMSGSIZE;

	used = 0;
	for (index = 0; index < count; index++) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[first + index];
		void __user *aad_user =
			(void __user *)(uintptr_t)request->aad_ptr;
		void __user *src_user =
			(void __user *)(uintptr_t)request->src_ptr;
		unsigned int padded = request->data_len ?
			ALIGN(request->data_len, AES_BLOCK_SIZE) : 0;
		u32 aad_offset = used;
		u32 data_offset;
		u8 counter[AES_BLOCK_SIZE];
		struct scatterlist ciphertext;

		if (request->aad_len &&
		    copy_from_user(payload + used, aad_user,
				   request->aad_len))
			return -EFAULT;
		used += request->aad_len;
		data_offset = ALIGN(used, AES_BLOCK_SIZE);
		if (data_offset > used)
			memset(payload + used, 0, data_offset - used);
		used = data_offset;
		if (request->data_len &&
		    copy_from_user(payload + used, src_user,
				   request->data_len))
			return -EFAULT;
		if (padded > request->data_len)
			memset(payload + used + request->data_len, 0,
			       padded - request->data_len);
		used += padded;
		writel(aad_offset, &slot->requests[index].aad_offset);
		writel(request->aad_len, &slot->requests[index].aad_length);
		writel(data_offset, &slot->requests[index].data_offset);
		writel(request->data_len, &slot->requests[index].data_length);
		if (padded) {
			sg_init_one(&ciphertext, payload + data_offset,
				    padded);
			memcpy(counter, request->iv,
			       ONEKVM_OFFLOAD_GCM_IV_SIZE);
			put_unaligned_be32(2, counter +
					   ONEKVM_OFFLOAD_GCM_IV_SIZE);
			error = cvitek_spacc_aes_ctr_encrypt_sg(
				&ciphertext, &ciphertext, padded,
				context->key, context->key_len, counter);
			memzero_explicit(counter, sizeof(counter));
			if (error)
				return error;
		}
		*byte_count += request->aad_len + request->data_len;
	}

	seq = offload_ring_seq++;
	if (!seq)
		seq = offload_ring_seq++;
	memcpy_toio(slot->hash_subkey, context->hash_subkey,
		    sizeof(context->hash_subkey));
	writel(lower_32_bits(offload_ring_payload_phys[idx]),
	       &slot->payload_phys);
	writel(count, &slot->count);
	writel(used, &slot->payload_used);
	writel(0, &slot->status);
	writel(seq, &slot->seq);
	wmb();
	writel(ONEKVM_GHASH_SLOT_READY, &slot->state);
	/* Uncached posted write: make READY visible before we wait. */
	(void)readl(&slot->state);
	atomic64_inc(&offload_rtos_ghash_batches);
	atomic64_add(count, &offload_rtos_ghash_packets);
	*count_out = count;
	return 0;
}

static int onekvm_offload_encrypt_ring(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *requests,
	unsigned int request_count, unsigned int *completed)
{
	struct onekvm_ghash_shm __iomem *shm = offload_rtos_ghash_shm;
	unsigned int published_first[ONEKVM_GHASH_RING_SLOTS];
	unsigned int published_count[ONEKVM_GHASH_RING_SLOTS];
	unsigned int first = 0;
	unsigned int prod = 0;
	unsigned int cons = 0;
	unsigned int inflight = 0;
	u64 started_ns;
	u64 byte_count = 0;
	u64 timeout_ns;
	int error = 0;

	*completed = 0;
	mutex_lock(&offload_rtos_ghash_lock);
	if (!offload_rtos_ghash_enabled || !shm ||
	    !offload_ring_payload[0]) {
		error = -ENODEV;
		goto unlock;
	}
	started_ns = ktime_get_ns();
	timeout_ns = (u64)READ_ONCE(offload_rtos_ghash_timeout_ms) *
		     NSEC_PER_MSEC;

	while (first < request_count || inflight) {
		while (first < request_count &&
		       inflight < ONEKVM_GHASH_RING_SLOTS) {
			struct onekvm_ghash_slot __iomem *slot =
				&shm->slots[prod];
			unsigned int count = request_count;

			error = onekvm_offload_ring_claim(
				slot, ktime_get_ns() + timeout_ns);
			if (error)
				goto reset;
			error = onekvm_offload_ring_publish(
				context, requests, first, &count, prod,
				&byte_count);
			if (error)
				goto reset;
			published_first[prod] = first;
			published_count[prod] = count;
			first += count;
			prod = (prod + 1) % ONEKVM_GHASH_RING_SLOTS;
			inflight++;
		}

		{
			struct onekvm_ghash_slot __iomem *slot =
				&shm->slots[cons];
			u8 *payload = onekvm_offload_slot_payload(cons);
			unsigned int count = published_count[cons];

			error = onekvm_offload_wait_slot_state(
				slot, ONEKVM_GHASH_SLOT_DONE,
				ktime_get_ns() + timeout_ns);
			if (error == -ETIMEDOUT) {
				pr_warn_ratelimited(
					"OneKVM crypto offload: C906L GHASH slot %u timeout state=%u jobs=%llu\n",
					cons, readl(&slot->state),
					readq(&shm->jobs));
				error = onekvm_offload_harvest_slot(
					context, requests,
					published_first[cons], count,
					payload, slot, completed, false);
				if (error)
					goto reset;
				atomic64_add(count,
					     &offload_rtos_ghash_fallbacks);
			} else if (error) {
				goto reset;
			} else {
				error = onekvm_offload_harvest_slot(
					context, requests,
					published_first[cons], count,
					payload, slot, completed, true);
				if (error)
					goto reset;
			}
			cons = (cons + 1) % ONEKVM_GHASH_RING_SLOTS;
			inflight--;
		}
	}
	atomic64_add(byte_count, &offload_rtos_ghash_bytes);
	atomic64_add(ktime_get_ns() - started_ns, &offload_rtos_ghash_ns);
	atomic64_add(ktime_get_ns() - started_ns, &offload_crypto_ns);
	goto unlock;

reset:
	onekvm_offload_ring_reset(shm);
unlock:
	mutex_unlock(&offload_rtos_ghash_lock);
	return error;
}

static void onekvm_offload_free_crypto(struct onekvm_offload_context *context)
{
	if (context->ghash_desc) {
		kfree_sensitive(context->ghash_desc);
		context->ghash_desc = NULL;
	}
	if (context->ghash) {
		crypto_free_shash(context->ghash);
		context->ghash = NULL;
	}
	if (context->aes) {
		crypto_free_cipher(context->aes);
		context->aes = NULL;
	}
	memzero_explicit(context->key, sizeof(context->key));
	memzero_explicit(context->hash_subkey, sizeof(context->hash_subkey));
	context->key_len = 0;
	context->rtos_verify_remaining = 0;
}

static int onekvm_offload_set_key(struct onekvm_offload_context *context,
				  void __user *argument)
{
	struct onekvm_offload_key_config config;
	struct crypto_shash *ghash;
	struct shash_desc *ghash_desc;
	struct crypto_cipher *aes;
	u8 hash_subkey[AES_BLOCK_SIZE] = { 0 };
	const char *ghash_driver;
	int error;

	if (copy_from_user(&config, argument, sizeof(config)))
		return -EFAULT;
	if (config.version != ONEKVM_OFFLOAD_ABI_VERSION || config.reserved ||
	    config.auth_size != ONEKVM_OFFLOAD_GCM_TAG_SIZE ||
	    (config.key_len != 16 && config.key_len != 32)) {
		error = -EINVAL;
		goto clear_config;
	}
	if (!cvitek_spacc_kernel_api_ready()) {
		error = -ENODEV;
		goto clear_config;
	}

	ghash = crypto_alloc_shash(ONEKVM_OFFLOAD_GHASH_NAME, 0, 0);
	if (IS_ERR(ghash)) {
		error = PTR_ERR(ghash);
		goto clear_config;
	}
	aes = crypto_alloc_cipher(ONEKVM_OFFLOAD_AES_NAME, 0, 0);
	if (IS_ERR(aes)) {
		error = PTR_ERR(aes);
		goto free_ghash;
	}
	error = crypto_cipher_setkey(aes, config.key, config.key_len);
	if (error)
		goto free_aes;
	crypto_cipher_encrypt_one(aes, hash_subkey, hash_subkey);
	error = crypto_shash_setkey(ghash, hash_subkey, sizeof(hash_subkey));
	if (error)
		goto free_aes;

	ghash_desc = kmalloc(sizeof(*ghash_desc) +
			     crypto_shash_descsize(ghash), GFP_KERNEL);
	if (!ghash_desc) {
		error = -ENOMEM;
		goto free_aes;
	}
	ghash_desc->tfm = ghash;

	onekvm_offload_free_crypto(context);
	context->ghash = ghash;
	context->ghash_desc = ghash_desc;
	context->aes = aes;
	memcpy(context->key, config.key, config.key_len);
	memcpy(context->hash_subkey, hash_subkey, sizeof(hash_subkey));
	context->key_len = config.key_len;
	context->rtos_verify_remaining = ONEKVM_OFFLOAD_RTOS_VERIFY_PACKETS;
	ghash_driver = crypto_tfm_alg_driver_name(crypto_shash_tfm(ghash));
	mutex_lock(&offload_driver_name_lock);
	if (READ_ONCE(offload_rtos_ghash_enabled))
		scnprintf(offload_driver_name, sizeof(offload_driver_name),
			  "onekvm-gcm(cvitek-spacc,ghash-c906l+%s)",
			  ghash_driver);
	else
		scnprintf(offload_driver_name, sizeof(offload_driver_name),
			  "onekvm-gcm(cvitek-spacc,%s)", ghash_driver);
	mutex_unlock(&offload_driver_name_lock);
	pr_info_once("OneKVM crypto offload: AES-GCM CTR=cvitek-spacc GHASH=%s\n",
		     ghash_driver);
	error = 0;
	goto clear_config;

free_aes:
	crypto_free_cipher(aes);
free_ghash:
	crypto_free_shash(ghash);
clear_config:
	memzero_explicit(hash_subkey, sizeof(hash_subkey));
	memzero_explicit(&config, sizeof(config));
	return error;
}

static int onekvm_offload_ghash(struct onekvm_offload_context *context,
				const u8 *aad, unsigned int aad_len,
				struct scatterlist *ciphertext,
				unsigned int ciphertext_len, u8 *tag)
{
	struct sg_mapping_iter iterator;
	u8 lengths[AES_BLOCK_SIZE];
	u8 padding[AES_BLOCK_SIZE] = { 0 };
	unsigned int remaining;
	unsigned int count;
	int entries;
	unsigned int remainder;
	int error;

	error = crypto_shash_init(context->ghash_desc);
	if (error)
		return error;
	if (aad_len) {
		error = crypto_shash_update(context->ghash_desc, aad, aad_len);
		if (error)
			return error;
		remainder = aad_len % AES_BLOCK_SIZE;
		if (remainder) {
			error = crypto_shash_update(context->ghash_desc, padding,
						 AES_BLOCK_SIZE - remainder);
			if (error)
				return error;
		}
	}
	if (ciphertext_len) {
		entries = sg_nents_for_len(ciphertext, ciphertext_len);
		if (entries < 0)
			return entries;
		remaining = ciphertext_len;
		sg_miter_start(&iterator, ciphertext, entries,
			       SG_MITER_FROM_SG);
		while (remaining && sg_miter_next(&iterator)) {
			count = min_t(unsigned int, remaining, iterator.length);
			error = crypto_shash_update(context->ghash_desc,
						   iterator.addr, count);
			if (error)
				break;
			remaining -= count;
		}
		sg_miter_stop(&iterator);
		if (error)
			return error;
		if (remaining)
			return -EFAULT;
		remainder = ciphertext_len % AES_BLOCK_SIZE;
		if (remainder) {
			error = crypto_shash_update(context->ghash_desc, padding,
						 AES_BLOCK_SIZE - remainder);
			if (error)
				return error;
		}
	}
	put_unaligned_be64((u64)aad_len * 8, lengths);
	put_unaligned_be64((u64)ciphertext_len * 8, lengths + 8);
	error = crypto_shash_update(context->ghash_desc, lengths,
				    sizeof(lengths));
	if (!error)
		error = crypto_shash_final(context->ghash_desc, tag);
	memzero_explicit(lengths, sizeof(lengths));
	return error;
}

static int onekvm_offload_validate_encrypt_request(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters)
{
	if (parameters->version != ONEKVM_OFFLOAD_ABI_VERSION ||
	    parameters->flags ||
	    memchr_inv(parameters->reserved, 0,
		       sizeof(parameters->reserved)))
		return -EINVAL;
	if (!context->key_len || !cvitek_spacc_kernel_api_ready())
		return -ENOKEY;
	if (parameters->aad_len > ONEKVM_OFFLOAD_MAX_INPUT ||
	    parameters->data_len > ONEKVM_OFFLOAD_MAX_INPUT ||
	    parameters->aad_len + parameters->data_len >
		    ONEKVM_OFFLOAD_MAX_INPUT)
		return -EMSGSIZE;
	if ((parameters->aad_len && !parameters->aad_ptr) ||
	    (parameters->data_len && !parameters->src_ptr) ||
	    !parameters->dst_ptr)
		return -EFAULT;
	return 0;
}

static int onekvm_offload_software_ghash(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters,
	struct scatterlist *ciphertext, u8 *tag)
{
	void __user *aad_user =
		(void __user *)(uintptr_t)parameters->aad_ptr;

	if (parameters->aad_len &&
	    copy_from_user(context->input, aad_user, parameters->aad_len))
		return -EFAULT;
	return onekvm_offload_ghash(context, context->input,
		parameters->aad_len, ciphertext, parameters->data_len, tag);
}

static int onekvm_offload_write_gcm_tag(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters,
	const u8 *raw_tag)
{
	void __user *dst_user =
		(void __user *)(uintptr_t)parameters->dst_ptr;
	u8 counter[AES_BLOCK_SIZE];
	u8 tag_mask[AES_BLOCK_SIZE];
	u8 tag[AES_BLOCK_SIZE];
	unsigned int index;
	int error = 0;

	memcpy(counter, parameters->iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
	put_unaligned_be32(1, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
	crypto_cipher_encrypt_one(context->aes, tag_mask, counter);
	memcpy(tag, raw_tag, sizeof(tag));
	for (index = 0; index < ONEKVM_OFFLOAD_GCM_TAG_SIZE; index++)
		tag[index] ^= tag_mask[index];
	if (copy_to_user((u8 __user *)dst_user + parameters->data_len, tag,
			 ONEKVM_OFFLOAD_GCM_TAG_SIZE)) {
		error = -EFAULT;
		goto clear_temporary;
	}
	atomic64_inc(&offload_tx_packets);
	atomic64_add(parameters->data_len, &offload_tx_bytes);
clear_temporary:
	memzero_explicit(counter, sizeof(counter));
	memzero_explicit(tag_mask, sizeof(tag_mask));
	memzero_explicit(tag, sizeof(tag));
	return error;
}

static int onekvm_offload_finish_gcm(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters,
	struct scatterlist *ciphertext)
{
	u8 tag[AES_BLOCK_SIZE];
	int error;

	error = onekvm_offload_software_ghash(context, parameters,
					      ciphertext, tag);
	if (!error)
		error = onekvm_offload_write_gcm_tag(context, parameters, tag);
	memzero_explicit(tag, sizeof(tag));
	return error;
}

static int onekvm_offload_encrypt_parameters(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *request)
{
	struct onekvm_offload_encrypt_request parameters = *request;
	struct scatterlist ciphertext;
	void __user *src_user;
	void __user *dst_user;
	u64 started_ns;
	u8 counter[AES_BLOCK_SIZE];
	bool in_place;
	int error;

	error = onekvm_offload_validate_encrypt_request(context, &parameters);
	if (error)
		return error;

	src_user = (void __user *)(uintptr_t)parameters.src_ptr;
	dst_user = (void __user *)(uintptr_t)parameters.dst_ptr;
	in_place = parameters.data_len &&
		   parameters.src_ptr == parameters.dst_ptr;
	if (!in_place && parameters.data_len &&
	    onekvm_offload_ranges_overlap((unsigned long)src_user,
					  parameters.data_len,
					  (unsigned long)dst_user,
					  parameters.data_len))
		return -EINVAL;

	/* The CVITEK kernel API already copies every scatterlist into its own
	 * contiguous DMA buffer. Pinning userspace pages here therefore adds GUP,
	 * dirty-page and scatterlist overhead without removing a data copy. Stage
	 * the small SRTP payload next to its AAD instead; this also keeps the hot
	 * batch path independent of userspace page layout. */
	if (parameters.data_len &&
	    copy_from_user(context->input + parameters.aad_len, src_user,
			   parameters.data_len))
		return -EFAULT;
	sg_init_one(&ciphertext, context->input + parameters.aad_len,
		    parameters.data_len);

	memcpy(counter, parameters.iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
	put_unaligned_be32(2, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
	started_ns = ktime_get_ns();
	if (parameters.data_len) {
		error = cvitek_spacc_aes_ctr_encrypt_sg(
			&ciphertext, &ciphertext,
			parameters.data_len, context->key, context->key_len,
			counter);
		if (error)
			goto clear_temporary;
		if (copy_to_user(dst_user,
				 context->input + parameters.aad_len,
				 parameters.data_len)) {
			error = -EFAULT;
			goto clear_temporary;
		}
	}
	error = onekvm_offload_finish_gcm(context, &parameters, &ciphertext);
	if (error)
		goto clear_temporary;
	atomic64_add(ktime_get_ns() - started_ns, &offload_crypto_ns);
clear_temporary:
	memzero_explicit(counter, sizeof(counter));
	memzero_explicit(context->input,
			 parameters.aad_len + parameters.data_len);
	return error;
}

static int onekvm_offload_encrypt(struct onekvm_offload_context *context,
				  void __user *argument)
{
	struct onekvm_offload_encrypt_request parameters;

	if (copy_from_user(&parameters, argument, sizeof(parameters)))
		return -EFAULT;
	return onekvm_offload_encrypt_parameters(context, &parameters);
}

static int onekvm_offload_encrypt_batch_chunk(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *requests,
	unsigned int request_count, unsigned int *completed)
{
	unsigned int data_offsets[ONEKVM_OFFLOAD_MAX_BATCH];
	unsigned int data_used = 0;
	unsigned int chunk_count = 0;
	unsigned int request_index;
	u64 started_ns;
	bool rtos_tags = false;
	int error = 0;

	*completed = 0;
	if (READ_ONCE(offload_rtos_ghash_enabled) &&
	    READ_ONCE(offload_use_rtos_ghash))
		return onekvm_offload_encrypt_ring(context, requests,
						   request_count, completed);
	while (chunk_count < request_count) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[chunk_count];
		void __user *src_user =
			(void __user *)(uintptr_t)request->src_ptr;
		void __user *dst_user =
			(void __user *)(uintptr_t)request->dst_ptr;

		unsigned int padded = request->data_len ?
			ALIGN(request->data_len, AES_BLOCK_SIZE) : 0;

		if (data_used + padded > ONEKVM_OFFLOAD_BATCH_BUFFER_SIZE)
			break;
		if (request->data_len && request->src_ptr != request->dst_ptr &&
		    onekvm_offload_ranges_overlap((unsigned long)src_user,
						  request->data_len,
						  (unsigned long)dst_user,
						  request->data_len)) {
			error = -EINVAL;
			goto clear_buffers;
		}
		if (request->data_len &&
		    copy_from_user(context->batch_data + data_used, src_user,
				   request->data_len)) {
			error = -EFAULT;
			goto clear_buffers;
		}
		if (padded > request->data_len)
			memset(context->batch_data + data_used +
				       request->data_len,
			       0, padded - request->data_len);
		data_offsets[chunk_count] = data_used;
		data_used += padded;
		chunk_count++;
	}
	if (!chunk_count)
		return -EMSGSIZE;

	started_ns = ktime_get_ns();
	if (READ_ONCE(offload_ctr_chain)) {
		struct cvitek_spacc_ctr_job jobs[CVITEK_SPACC_MAX_CHAIN];
		u8 ivs[CVITEK_SPACC_MAX_CHAIN][AES_BLOCK_SIZE];
		unsigned int job_count = 0;

		error = 0;
		for (request_index = 0; request_index < chunk_count;
		     request_index++) {
			const struct onekvm_offload_encrypt_request *request =
				&requests[request_index];

			if (!request->data_len)
				continue;
			if (job_count == CVITEK_SPACC_MAX_CHAIN) {
				error = cvitek_spacc_aes_ctr_encrypt_many(
					jobs, job_count, context->key,
					context->key_len);
				if (error)
					break;
				job_count = 0;
			}
			memcpy(ivs[job_count], request->iv,
			       ONEKVM_OFFLOAD_GCM_IV_SIZE);
			put_unaligned_be32(2, ivs[job_count] +
					   ONEKVM_OFFLOAD_GCM_IV_SIZE);
			jobs[job_count].buf = context->batch_data +
				data_offsets[request_index];
			jobs[job_count].length =
				ALIGN(request->data_len, AES_BLOCK_SIZE);
			jobs[job_count].iv = ivs[job_count];
			job_count++;
		}
		if (!error && job_count)
			error = cvitek_spacc_aes_ctr_encrypt_many(
				jobs, job_count, context->key,
				context->key_len);
		if (error) {
			pr_warn_once("OneKVM crypto offload: CTR chain failed %d, per-packet fallback\n",
				     error);
			WRITE_ONCE(offload_ctr_chain, false);
		} else {
			goto ctr_done;
		}
	}
	for (request_index = 0; request_index < chunk_count; request_index++) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[request_index];
		u8 *data = context->batch_data + data_offsets[request_index];
		struct scatterlist ciphertext;
		u8 counter[AES_BLOCK_SIZE];
		unsigned int padded;

		if (!request->data_len)
			continue;
		padded = ALIGN(request->data_len, AES_BLOCK_SIZE);
		sg_init_one(&ciphertext, data, padded);
		memcpy(counter, request->iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
		put_unaligned_be32(2, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
		error = cvitek_spacc_aes_ctr_encrypt_sg(
			&ciphertext, &ciphertext, padded,
			context->key, context->key_len, counter);
		memzero_explicit(counter, sizeof(counter));
		if (error)
			goto clear_buffers;
	}
ctr_done:

	for (request_index = 0; request_index < chunk_count;
	     request_index++) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[request_index];
		struct scatterlist ciphertext;
		void __user *dst_user =
			(void __user *)(uintptr_t)request->dst_ptr;
		u8 *data = context->batch_data + data_offsets[request_index];
		u8 software_tag[AES_BLOCK_SIZE];
		const u8 *raw_tag = context->batch_tags[request_index];

		if (request->data_len &&
		    copy_to_user(dst_user, data, request->data_len)) {
			error = -EFAULT;
			goto clear_buffers;
		}
		sg_init_one(&ciphertext, data, request->data_len);
		if (!rtos_tags || context->rtos_verify_remaining) {
			error = onekvm_offload_software_ghash(context, request,
						      &ciphertext, software_tag);
			if (error) {
				memzero_explicit(software_tag,
						 sizeof(software_tag));
				goto clear_buffers;
			}
			if (!rtos_tags) {
				raw_tag = software_tag;
			} else if (crypto_memneq(software_tag, raw_tag,
						 AES_BLOCK_SIZE)) {
				atomic64_inc(&offload_rtos_ghash_errors);
				atomic64_add(chunk_count - request_index,
					     &offload_rtos_ghash_fallbacks);
				onekvm_offload_disable_rtos_ghash(
					"verification mismatch");
				rtos_tags = false;
				raw_tag = software_tag;
			} else {
				context->rtos_verify_remaining--;
				atomic64_inc(&offload_rtos_ghash_verified);
			}
		}
		error = onekvm_offload_write_gcm_tag(context, request, raw_tag);
		memzero_explicit(software_tag, sizeof(software_tag));
		if (error)
			goto clear_buffers;
		(*completed)++;
	}
	atomic64_add(ktime_get_ns() - started_ns, &offload_crypto_ns);

clear_buffers:
	memzero_explicit(context->batch_data, data_used);
	return error;
}

static int onekvm_offload_encrypt_batch(
	struct onekvm_offload_context *context, void __user *argument)
{
	struct onekvm_offload_encrypt_request *requests;
	struct onekvm_offload_batch_request batch;
	void __user *requests_user;
	size_t requests_size;
	unsigned int index;
	int error = 0;

	if (copy_from_user(&batch, argument, sizeof(batch)))
		return -EFAULT;
	if (batch.version != ONEKVM_OFFLOAD_ABI_VERSION || batch.flags ||
	    batch.completed || !batch.count ||
	    batch.count > ONEKVM_OFFLOAD_MAX_BATCH || !batch.requests_ptr)
		return -EINVAL;
	requests_size = array_size(batch.count, sizeof(*requests));
	requests_user = (void __user *)(uintptr_t)batch.requests_ptr;
	requests = memdup_user(requests_user, requests_size);
	if (IS_ERR(requests))
		return PTR_ERR(requests);

	for (index = 0; index < batch.count; index++) {
		error = onekvm_offload_validate_encrypt_request(context,
								 &requests[index]);
		if (error)
			goto complete;
	}

	index = 0;
	while (index < batch.count) {
		unsigned int completed = 0;

		error = onekvm_offload_encrypt_batch_chunk(context,
			&requests[index], batch.count - index, &completed);
		batch.completed += completed;
		index += completed;
		if (error)
			break;
	}
	atomic64_inc(&offload_batch_calls);
	atomic64_add(batch.completed, &offload_batch_packets);
complete:
	kfree_sensitive(requests);
	if (copy_to_user(argument, &batch, sizeof(batch)) && !error)
		error = -EFAULT;
	return error;
}

static long onekvm_offload_ioctl(struct file *file, unsigned int command,
				 unsigned long argument)
{
	struct onekvm_offload_context *context = file->private_data;
	void __user *argument_user = (void __user *)argument;
	long result;

	mutex_lock(&context->lock);
	switch (command) {
	case ONEKVM_OFFLOAD_SET_KEY:
		result = onekvm_offload_set_key(context, argument_user);
		break;
	case ONEKVM_OFFLOAD_ENCRYPT:
		result = onekvm_offload_encrypt(context, argument_user);
		if (result) {
			atomic64_inc(&offload_tx_errors);
			atomic_set(&offload_last_error, result);
		}
		break;
	case ONEKVM_OFFLOAD_ENCRYPT_BATCH:
		result = onekvm_offload_encrypt_batch(context, argument_user);
		if (result) {
			atomic64_inc(&offload_tx_errors);
			atomic_set(&offload_last_error, result);
		}
		break;
	default:
		result = -ENOTTY;
		break;
	}
	mutex_unlock(&context->lock);
	return result;
}

static int onekvm_offload_open(struct inode *inode, struct file *file)
{
	struct onekvm_offload_context *context;

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	context->input = kmalloc(ONEKVM_OFFLOAD_MAX_INPUT +
				ONEKVM_OFFLOAD_GCM_TAG_SIZE, GFP_KERNEL);
	context->batch_data = kmalloc(ONEKVM_OFFLOAD_BATCH_BUFFER_SIZE,
				      GFP_KERNEL | GFP_DMA);
	context->batch_tags = kmalloc_array(ONEKVM_OFFLOAD_MAX_BATCH,
					    AES_BLOCK_SIZE, GFP_KERNEL);
	if (!context->input || !context->batch_data || !context->batch_tags)
		goto free_context;
	mutex_init(&context->lock);
	file->private_data = context;
	return 0;

free_context:
	kfree(context->batch_tags);
	kfree(context->batch_data);
	kfree(context->input);
	kfree(context);
	return -ENOMEM;
}

static int onekvm_offload_release(struct inode *inode, struct file *file)
{
	struct onekvm_offload_context *context = file->private_data;

	if (!context)
		return 0;
	mutex_lock(&context->lock);
	onekvm_offload_free_crypto(context);
	memzero_explicit(context->input, ONEKVM_OFFLOAD_MAX_INPUT +
			 ONEKVM_OFFLOAD_GCM_TAG_SIZE);
	memzero_explicit(context->batch_data,
			 ONEKVM_OFFLOAD_BATCH_BUFFER_SIZE);
	memzero_explicit(context->batch_tags,
			 ONEKVM_OFFLOAD_MAX_BATCH * AES_BLOCK_SIZE);
	kfree(context->batch_tags);
	kfree(context->batch_data);
	kfree(context->input);
	mutex_unlock(&context->lock);
	kfree(context);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations onekvm_offload_file_operations = {
	.owner = THIS_MODULE,
	.open = onekvm_offload_open,
	.release = onekvm_offload_release,
	.unlocked_ioctl = onekvm_offload_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = onekvm_offload_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice onekvm_offload_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = ONEKVM_OFFLOAD_NAME,
	.fops = &onekvm_offload_file_operations,
	.mode = 0600,
};

static ssize_t tx_packets_show(struct device *device,
			       struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_tx_packets));
}
static DEVICE_ATTR_RO(tx_packets);

static ssize_t tx_bytes_show(struct device *device,
			     struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_tx_bytes));
}
static DEVICE_ATTR_RO(tx_bytes);

static ssize_t tx_errors_show(struct device *device,
			      struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_tx_errors));
}
static DEVICE_ATTR_RO(tx_errors);

static ssize_t last_error_show(struct device *device,
			       struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n",
			 atomic_read(&offload_last_error));
}
static DEVICE_ATTR_RO(last_error);

static ssize_t crypto_ns_show(struct device *device,
			      struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_crypto_ns));
}
static DEVICE_ATTR_RO(crypto_ns);

static ssize_t batch_calls_show(struct device *device,
				struct device_attribute *attribute, char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_batch_calls));
}
static DEVICE_ATTR_RO(batch_calls);

static ssize_t batch_packets_show(struct device *device,
				  struct device_attribute *attribute,
				  char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_batch_packets));
}
static DEVICE_ATTR_RO(batch_packets);

static ssize_t batch_unique_pages_show(struct device *device,
				       struct device_attribute *attribute,
				       char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 atomic64_read(&offload_batch_unique_pages));
}
static DEVICE_ATTR_RO(batch_unique_pages);

static ssize_t rtos_ghash_ready_show(struct device *device,
				     struct device_attribute *attribute,
				     char *buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n",
			 READ_ONCE(offload_rtos_ghash_enabled) ? 1 : 0);
}
static DEVICE_ATTR_RO(rtos_ghash_ready);

#define ONEKVM_RTOS_GHASH_STAT_ATTR(_name) \
static ssize_t rtos_ghash_##_name##_show( \
	struct device *device, struct device_attribute *attribute, char *buffer) \
{ \
	return scnprintf(buffer, PAGE_SIZE, "%lld\n", \
		atomic64_read(&offload_rtos_ghash_##_name)); \
} \
static DEVICE_ATTR_RO(rtos_ghash_##_name)

ONEKVM_RTOS_GHASH_STAT_ATTR(batches);
ONEKVM_RTOS_GHASH_STAT_ATTR(packets);
ONEKVM_RTOS_GHASH_STAT_ATTR(bytes);
ONEKVM_RTOS_GHASH_STAT_ATTR(ns);
ONEKVM_RTOS_GHASH_STAT_ATTR(verified);
ONEKVM_RTOS_GHASH_STAT_ATTR(fallbacks);
ONEKVM_RTOS_GHASH_STAT_ATTR(errors);

static ssize_t driver_show(struct device *device,
			   struct device_attribute *attribute, char *buffer)
{
	ssize_t length;

	mutex_lock(&offload_driver_name_lock);
	length = scnprintf(buffer, PAGE_SIZE, "%s\n", offload_driver_name);
	mutex_unlock(&offload_driver_name_lock);
	return length;
}
static DEVICE_ATTR_RO(driver);

static struct attribute *onekvm_offload_attrs[] = {
	&dev_attr_tx_packets.attr,
	&dev_attr_tx_bytes.attr,
	&dev_attr_tx_errors.attr,
	&dev_attr_last_error.attr,
	&dev_attr_crypto_ns.attr,
	&dev_attr_batch_calls.attr,
	&dev_attr_batch_packets.attr,
	&dev_attr_batch_unique_pages.attr,
	&dev_attr_rtos_ghash_ready.attr,
	&dev_attr_rtos_ghash_batches.attr,
	&dev_attr_rtos_ghash_packets.attr,
	&dev_attr_rtos_ghash_bytes.attr,
	&dev_attr_rtos_ghash_ns.attr,
	&dev_attr_rtos_ghash_verified.attr,
	&dev_attr_rtos_ghash_fallbacks.attr,
	&dev_attr_rtos_ghash_errors.attr,
	&dev_attr_driver.attr,
	NULL,
};
ATTRIBUTE_GROUPS(onekvm_offload);

static void onekvm_offload_mbox_init(void)
{
	struct device_node *node;
	int irq;
	int error;
	unsigned int i;

	init_waitqueue_head(&offload_ghash_wq);
	node = of_find_compatible_node(NULL, NULL, "cvitek,rtos_cmdqu");
	if (!node)
		return;
	irq = of_irq_get(node, 0);
	of_node_put(node);
	if (irq <= 0)
		return;
	offload_mbox_base = ioremap(OFFLOAD_MBOX_PHYS, OFFLOAD_MBOX_SIZE);
	if (!offload_mbox_base)
		return;
	error = request_irq(irq, onekvm_offload_mbox_irq, IRQF_SHARED,
			    "onekvm-ghash-mbox", &offload_ghash_wq);
	if (error) {
		iounmap(offload_mbox_base);
		offload_mbox_base = NULL;
		pr_warn("OneKVM crypto offload: mailbox IRQ %d failed %d\n",
			irq, error);
		return;
	}
	offload_mbox_irq = irq;
	/* Unmask CPU1 mailbox IRQs; SRAM context is uninitialized garbage. */
	writeb(0, offload_mbox_base + OFFLOAD_MBOX_CLR_CPU1 + 4);
	for (i = 0; i < OFFLOAD_MBOX_SLOTS; i++) {
		writel(0, offload_mbox_base + OFFLOAD_MBOX_CONTEXT + i * 8);
		writel(0, offload_mbox_base + OFFLOAD_MBOX_CONTEXT + i * 8 + 4);
	}
	pr_info("OneKVM crypto offload: mailbox IRQ %d for GHASH wait_event\n",
		offload_mbox_irq);
}

static void onekvm_offload_mbox_exit(void)
{
	if (offload_mbox_irq >= 0) {
		free_irq(offload_mbox_irq, &offload_ghash_wq);
		offload_mbox_irq = -1;
	}
	if (offload_mbox_base) {
		iounmap(offload_mbox_base);
		offload_mbox_base = NULL;
	}
}

static void onekvm_offload_ring_payload_free(void)
{
	unsigned int i;

	for (i = 0; i < ONEKVM_GHASH_RING_SLOTS; i++) {
		kfree(offload_ring_payload_raw[i]);
		offload_ring_payload_raw[i] = NULL;
		offload_ring_payload[i] = NULL;
		offload_ring_payload_phys[i] = 0;
	}
}

static int onekvm_offload_ring_payload_alloc(void)
{
	unsigned int i;

	for (i = 0; i < ONEKVM_GHASH_RING_SLOTS; i++) {
		offload_ring_payload_raw[i] =
			kmalloc(ONEKVM_GHASH_SLOT_PAYLOAD + AES_BLOCK_SIZE,
				GFP_KERNEL | GFP_DMA);
		if (!offload_ring_payload_raw[i]) {
			onekvm_offload_ring_payload_free();
			return -ENOMEM;
		}
		offload_ring_payload[i] =
			PTR_ALIGN(offload_ring_payload_raw[i], AES_BLOCK_SIZE);
		offload_ring_payload_phys[i] =
			virt_to_phys(offload_ring_payload[i]);
		if (offload_ring_payload_phys[i] < 0x80000000ULL ||
		    offload_ring_payload_phys[i] +
			    ONEKVM_GHASH_SLOT_PAYLOAD > 0x8FE00000ULL) {
			pr_warn("OneKVM crypto offload: GFP_DMA payload %#llx outside C906L window\n",
				(unsigned long long)
					offload_ring_payload_phys[i]);
			onekvm_offload_ring_payload_free();
			return -ENOMEM;
		}
	}
	return 0;
}

static void onekvm_offload_ghash_unmap(void)
{
	onekvm_offload_ring_payload_free();
	if (offload_ghash_cached && offload_ghash_cpu)
		memunmap(offload_ghash_cpu);
	else if (offload_rtos_ghash_iomem)
		iounmap(offload_rtos_ghash_iomem);
	offload_ghash_cpu = NULL;
	offload_rtos_ghash_iomem = NULL;
	offload_rtos_ghash_shm = NULL;
}

static int __init onekvm_offload_init(void)
{
	int error;
	unsigned int slot;

	if (!cvitek_spacc_kernel_api_ready())
		return -ENODEV;
	onekvm_offload_mbox_init();
	/* Headers stay uncached so C906L sees READY. Ciphertext lives in
	 * GFP_DMA; SPACC already knows that path, and C906L GHASHes via
	 * payload_phys instead of the SHM that collides with OLED. */
	offload_rtos_ghash_iomem = ioremap(ONEKVM_GHASH_SHM_PHYS,
					   ONEKVM_GHASH_SHM_SIZE);
	offload_ghash_cpu = offload_rtos_ghash_iomem;
	offload_rtos_ghash_shm = offload_rtos_ghash_iomem;
	offload_ghash_cached = false;
	if (offload_rtos_ghash_shm) {
		if (readl(&offload_rtos_ghash_shm->magic) ==
				ONEKVM_GHASH_SHM_MAGIC &&
		    readl(&offload_rtos_ghash_shm->version) ==
				ONEKVM_GHASH_SHM_VERSION &&
		    readl(&offload_rtos_ghash_shm->size) ==
				ONEKVM_GHASH_SHM_SIZE &&
		    readl(&offload_rtos_ghash_shm->slot_count) ==
				ONEKVM_GHASH_RING_SLOTS &&
		    (readl(&offload_rtos_ghash_shm->flags) &
				ONEKVM_GHASH_FLAG_READY) &&
		    !onekvm_offload_ring_payload_alloc()) {
			offload_rtos_ghash_enabled = true;
			writel(0, &offload_rtos_ghash_shm->prod);
			writel(0, &offload_rtos_ghash_shm->cons);
			writel(0, &offload_rtos_ghash_shm->done);
			for (slot = 0; slot < ONEKVM_GHASH_RING_SLOTS; slot++) {
				writel(ONEKVM_GHASH_SLOT_EMPTY,
				       &offload_rtos_ghash_shm->slots[slot]
						.state);
				writel(0, &offload_rtos_ghash_shm->slots[slot]
						  .status);
			}
			wmb();
			pr_info("OneKVM crypto offload: C906L GHASH ring ready (GFP_DMA payload phys=%pap)\n",
				&offload_ring_payload_phys[0]);
		} else {
			onekvm_offload_ring_payload_free();
			pr_info("OneKVM crypto offload: C906L GHASH unavailable, using Linux fallback\n");
		}
	}
	error = misc_register(&onekvm_offload_device);
	if (error) {
		onekvm_offload_ghash_unmap();
		return error;
	}
	error = sysfs_create_groups(&onekvm_offload_device.this_device->kobj,
				   onekvm_offload_groups);
	if (error) {
		misc_deregister(&onekvm_offload_device);
		onekvm_offload_ghash_unmap();
		return error;
	}
	pr_info("OneKVM crypto offload ABI v%u registered\n",
		ONEKVM_OFFLOAD_ABI_VERSION);
	return 0;
}

static void __exit onekvm_offload_exit(void)
{
	WRITE_ONCE(offload_rtos_ghash_enabled, false);
	sysfs_remove_groups(&onekvm_offload_device.this_device->kobj,
			    onekvm_offload_groups);
	misc_deregister(&onekvm_offload_device);
	onekvm_offload_ghash_unmap();
	onekvm_offload_mbox_exit();
}

module_init(onekvm_offload_init);
module_exit(onekvm_offload_exit);

MODULE_DESCRIPTION("OneKVM AES-GCM userspace TX offload ABI");
MODULE_AUTHOR("OneKVM");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
