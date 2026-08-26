// SPDX-License-Identifier: GPL-2.0-only
/* OneKVM low-overhead userspace AES-GCM TX offload ABI. */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>

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
#define ONEKVM_SPACC_BASE 0x02060000
#define ONEKVM_SPACC_SIZE 0x200
#define ONEKVM_OFFLOAD_RTOS_VERIFY_PACKETS 128

static unsigned int offload_rtos_ghash_timeout_ms = 250;
module_param_named(rtos_ghash_timeout_ms, offload_rtos_ghash_timeout_ms,
		   uint, 0644);
MODULE_PARM_DESC(rtos_ghash_timeout_ms,
		 "C906L GHASH IPC timeout in milliseconds");

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
static bool offload_rtos_ghash_enabled;
static u32 offload_rtos_ghash_next_seq = 1;

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

static int onekvm_offload_rtos_ghash(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *requests,
	const unsigned int *data_offsets, unsigned int request_count)
{
	struct onekvm_ghash_shm __iomem *shm = offload_rtos_ghash_shm;
	unsigned int first = 0;
	int error = 0;

	mutex_lock(&offload_rtos_ghash_lock);
	if (!offload_rtos_ghash_enabled || !shm) {
		error = -ENODEV;
		goto unlock;
	}

	while (first < request_count) {
		unsigned int count = 0;
		unsigned int payload_used = 0;
		unsigned int index;
		u64 started_ns;
		u64 deadline_ns;
		u64 byte_count = 0;
		u32 seq;

		while (first + count < request_count &&
		       count < ONEKVM_GHASH_MAX_REQUESTS) {
			const struct onekvm_offload_encrypt_request *request =
				&requests[first + count];
			u32 length = request->aad_len + request->data_len;

			if (length > ONEKVM_GHASH_PAYLOAD_SIZE - payload_used)
				break;
			payload_used += length;
			count++;
		}
		if (!count) {
			error = -EMSGSIZE;
			goto unlock;
		}

		payload_used = 0;
		memcpy_toio(shm->hash_subkey, context->hash_subkey,
			    sizeof(context->hash_subkey));
		for (index = 0; index < count; index++) {
			const struct onekvm_offload_encrypt_request *request =
				&requests[first + index];
			struct onekvm_ghash_request __iomem *rtos_request =
				&shm->requests[index];
			void __user *aad_user =
				(void __user *)(uintptr_t)request->aad_ptr;
			u32 aad_offset = payload_used;
			u32 data_offset;

			if (request->aad_len) {
				if (copy_from_user(context->input, aad_user,
						   request->aad_len)) {
					error = -EFAULT;
					goto unlock;
				}
				memcpy_toio(shm->payload + payload_used,
					    context->input, request->aad_len);
				payload_used += request->aad_len;
			}
			data_offset = payload_used;
			if (request->data_len) {
				memcpy_toio(shm->payload + payload_used,
					    context->batch_data +
						data_offsets[first + index],
					    request->data_len);
				payload_used += request->data_len;
			}
			writel(aad_offset, &rtos_request->aad_offset);
			writel(request->aad_len, &rtos_request->aad_length);
			writel(data_offset, &rtos_request->data_offset);
			writel(request->data_len, &rtos_request->data_length);
			byte_count += request->aad_len + request->data_len;
		}

		writel(count, &shm->count);
		writel(payload_used, &shm->payload_used);
		writel(0, &shm->status);
		seq = offload_rtos_ghash_next_seq++;
		if (!seq)
			seq = offload_rtos_ghash_next_seq++;
		wmb();
		started_ns = ktime_get_ns();
		deadline_ns = started_ns +
			(u64)READ_ONCE(offload_rtos_ghash_timeout_ms) *
			NSEC_PER_MSEC;
		writel(seq, &shm->seq);
		while (readl(&shm->ack) != seq) {
			if (ktime_get_ns() >= deadline_ns) {
				error = -ETIMEDOUT;
				goto unlock;
			}
			usleep_range(50, 100);
		}
		rmb();
		error = (s32)readl(&shm->status);
		if (error)
			goto unlock;
		for (index = 0; index < count; index++)
			memcpy_fromio(context->batch_tags[first + index],
				      shm->requests[index].tag, AES_BLOCK_SIZE);
		atomic64_inc(&offload_rtos_ghash_batches);
		atomic64_add(count, &offload_rtos_ghash_packets);
		atomic64_add(byte_count, &offload_rtos_ghash_bytes);
		atomic64_add(ktime_get_ns() - started_ns,
			     &offload_rtos_ghash_ns);
		first += count;
	}

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
	while (chunk_count < request_count) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[chunk_count];
		void __user *src_user =
			(void __user *)(uintptr_t)request->src_ptr;
		void __user *dst_user =
			(void __user *)(uintptr_t)request->dst_ptr;

		if (data_used + request->data_len >
				ONEKVM_OFFLOAD_BATCH_BUFFER_SIZE)
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
		data_offsets[chunk_count] = data_used;
		data_used += request->data_len;
		chunk_count++;
	}
	if (!chunk_count)
		return -EMSGSIZE;

	started_ns = ktime_get_ns();
	for (request_index = 0; request_index < chunk_count; request_index++) {
		const struct onekvm_offload_encrypt_request *request =
			&requests[request_index];
		u8 *data = context->batch_data + data_offsets[request_index];
		struct scatterlist ciphertext;
		u8 counter[AES_BLOCK_SIZE];

		if (!request->data_len)
			continue;
		sg_init_one(&ciphertext, data, request->data_len);
		memcpy(counter, request->iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
		put_unaligned_be32(2, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
		error = cvitek_spacc_aes_ctr_encrypt_sg(
			&ciphertext, &ciphertext, request->data_len,
			context->key, context->key_len, counter);
		memzero_explicit(counter, sizeof(counter));
		if (error)
			goto clear_buffers;
	}

	if (READ_ONCE(offload_rtos_ghash_enabled)) {
		error = onekvm_offload_rtos_ghash(context, requests,
						 data_offsets, chunk_count);
		if (!error) {
			rtos_tags = true;
		} else if (error == -EFAULT) {
			goto clear_buffers;
		} else {
			atomic64_inc(&offload_rtos_ghash_errors);
			atomic64_add(chunk_count,
				     &offload_rtos_ghash_fallbacks);
			pr_warn("OneKVM crypto offload: C906L GHASH IPC error %d\n",
				error);
			onekvm_offload_disable_rtos_ghash("IPC failure");
			error = 0;
		}
	}

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
		if (result)
			atomic64_inc(&offload_tx_errors);
		break;
	case ONEKVM_OFFLOAD_ENCRYPT_BATCH:
		result = onekvm_offload_encrypt_batch(context, argument_user);
		if (result)
			atomic64_inc(&offload_tx_errors);
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
				      GFP_KERNEL);
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
	.llseek = no_llseek,
};

static struct miscdevice onekvm_offload_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = ONEKVM_OFFLOAD_NAME,
	.fops = &onekvm_offload_file_operations,
	.mode = 0600,
};

static struct resource onekvm_spacc_resources[] = {
	{
		.start = ONEKVM_SPACC_BASE,
		.end = ONEKVM_SPACC_BASE + ONEKVM_SPACC_SIZE - 1,
		.flags = IORESOURCE_MEM,
	},
};
static struct platform_device *onekvm_spacc_platform_device;

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

static void onekvm_offload_unregister_spacc(void)
{
	if (!onekvm_spacc_platform_device)
		return;
	platform_device_unregister(onekvm_spacc_platform_device);
	onekvm_spacc_platform_device = NULL;
}

static int __init onekvm_offload_init(void)
{
	int error;

	if (!cvitek_spacc_kernel_api_ready()) {
		onekvm_spacc_platform_device = platform_device_register_simple(
			"cvitek_spacc", PLATFORM_DEVID_NONE,
			onekvm_spacc_resources,
			ARRAY_SIZE(onekvm_spacc_resources));
		if (IS_ERR(onekvm_spacc_platform_device)) {
			error = PTR_ERR(onekvm_spacc_platform_device);
			onekvm_spacc_platform_device = NULL;
			return error;
		}
	}
	if (!cvitek_spacc_kernel_api_ready()) {
		onekvm_offload_unregister_spacc();
		return -ENODEV;
	}
	offload_rtos_ghash_iomem = ioremap(ONEKVM_GHASH_SHM_PHYS,
					   ONEKVM_GHASH_SHM_SIZE);
	if (offload_rtos_ghash_iomem) {
		offload_rtos_ghash_shm = offload_rtos_ghash_iomem;
		if (readl(&offload_rtos_ghash_shm->magic) ==
				ONEKVM_GHASH_SHM_MAGIC &&
		    readl(&offload_rtos_ghash_shm->version) ==
				ONEKVM_GHASH_SHM_VERSION &&
		    readl(&offload_rtos_ghash_shm->size) ==
				ONEKVM_GHASH_SHM_SIZE &&
		    readl(&offload_rtos_ghash_shm->max_requests) ==
				ONEKVM_GHASH_MAX_REQUESTS &&
		    (readl(&offload_rtos_ghash_shm->flags) &
				ONEKVM_GHASH_FLAG_READY)) {
			offload_rtos_ghash_next_seq =
				readl(&offload_rtos_ghash_shm->ack) + 1;
			if (!offload_rtos_ghash_next_seq)
				offload_rtos_ghash_next_seq = 1;
			offload_rtos_ghash_enabled = true;
			pr_info("OneKVM crypto offload: C906L GHASH ready\n");
		} else {
			pr_info("OneKVM crypto offload: C906L GHASH unavailable, using Linux fallback\n");
		}
	}
	error = misc_register(&onekvm_offload_device);
	if (error) {
		if (offload_rtos_ghash_iomem)
			iounmap(offload_rtos_ghash_iomem);
		onekvm_offload_unregister_spacc();
		return error;
	}
	error = sysfs_create_groups(&onekvm_offload_device.this_device->kobj,
				   onekvm_offload_groups);
	if (error) {
		misc_deregister(&onekvm_offload_device);
		if (offload_rtos_ghash_iomem)
			iounmap(offload_rtos_ghash_iomem);
		onekvm_offload_unregister_spacc();
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
	if (offload_rtos_ghash_iomem)
		iounmap(offload_rtos_ghash_iomem);
	onekvm_offload_unregister_spacc();
}

module_init(onekvm_offload_init);
module_exit(onekvm_offload_exit);

MODULE_DESCRIPTION("OneKVM AES-GCM userspace TX offload ABI");
MODULE_AUTHOR("OneKVM");
MODULE_LICENSE("GPL");
