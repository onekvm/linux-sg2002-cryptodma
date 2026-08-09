// SPDX-License-Identifier: GPL-2.0-only
/* OneKVM low-overhead userspace AES-GCM TX offload ABI. */

#include <crypto/aes.h>
#include <crypto/hash.h>
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>

#include "onekvm_sg2002_cryptodma.h"

#define ONEKVM_OFFLOAD_NAME "onekvm-crypto-offload"
#define ONEKVM_OFFLOAD_ABI_VERSION 1
#define ONEKVM_OFFLOAD_IOCTL_TYPE 0xb7
#define ONEKVM_OFFLOAD_GHASH_NAME "ghash-sg2002-cryptodma"
#define ONEKVM_OFFLOAD_AES_NAME "aes-generic"
#define ONEKVM_OFFLOAD_GCM_IV_SIZE 12
#define ONEKVM_OFFLOAD_GCM_TAG_SIZE 16
#define ONEKVM_OFFLOAD_MAX_INPUT (20 * 1024)
#define ONEKVM_OFFLOAD_MAX_BATCH 128
#define ONEKVM_SPACC_BASE 0x02060000
#define ONEKVM_SPACC_SIZE 0x200
#define ONEKVM_OFFLOAD_MAX_PAGES \
	DIV_ROUND_UP(ONEKVM_OFFLOAD_MAX_INPUT + PAGE_SIZE - 1, PAGE_SIZE)

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

struct onekvm_offload_user_buffer;
struct onekvm_offload_batch_page;

struct onekvm_offload_context {
	struct mutex lock;
	struct crypto_shash *ghash;
	struct shash_desc *ghash_desc;
	struct crypto_cipher *aes;
	u8 *input;
	struct onekvm_offload_user_buffer *batch_buffers;
	struct onekvm_offload_batch_page *batch_pages;
	u8 key[AES_MAX_KEY_SIZE];
	unsigned int key_len;
};

struct onekvm_offload_user_buffer {
	struct page *pages[ONEKVM_OFFLOAD_MAX_PAGES];
	struct scatterlist scatterlist[ONEKVM_OFFLOAD_MAX_PAGES];
	unsigned int page_count;
	bool writable;
};

struct onekvm_offload_batch_page {
	unsigned long user_address;
	struct page *page;
};

struct onekvm_offload_batch_pins {
	struct onekvm_offload_batch_page *pages;
	unsigned int count;
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
static char offload_driver_name[CRYPTO_MAX_ALG_NAME] = "unconfigured";
static DEFINE_MUTEX(offload_driver_name_lock);
static bool deduplicate_batch_pages = true;
module_param(deduplicate_batch_pages, bool, 0444);
MODULE_PARM_DESC(deduplicate_batch_pages,
	"pin each unique in-place userspace page once per batch");

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
	context->key_len = 0;
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
	context->key_len = config.key_len;
	ghash_driver = crypto_tfm_alg_driver_name(crypto_shash_tfm(ghash));
	mutex_lock(&offload_driver_name_lock);
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

static void onekvm_offload_unpin_user_buffer(
	struct onekvm_offload_user_buffer *buffer)
{
	unsigned int index;

	for (index = 0; index < buffer->page_count; index++) {
		if (buffer->writable)
			set_page_dirty_lock(buffer->pages[index]);
		unpin_user_page(buffer->pages[index]);
	}
	buffer->page_count = 0;
}

static int onekvm_offload_pin_user_buffer(
	struct onekvm_offload_user_buffer *buffer, u64 pointer,
	size_t length, bool writable)
{
	unsigned long address;
	unsigned long page_address;
	unsigned int page_offset;
	unsigned int page_count;
	unsigned int index;
	unsigned int count;
	unsigned int remaining = length;
	long pinned;

	memset(buffer, 0, sizeof(*buffer));
	if (!length)
		return 0;
	if (pointer > ULONG_MAX)
		return -EFAULT;
	address = (unsigned long)pointer;
	if (length > ULONG_MAX - address)
		return -EFAULT;
	page_offset = offset_in_page(address);
	page_count = DIV_ROUND_UP(page_offset + length, PAGE_SIZE);
	if (page_count > ONEKVM_OFFLOAD_MAX_PAGES)
		return -EMSGSIZE;
	page_address = address & PAGE_MASK;
	pinned = pin_user_pages_fast(page_address, page_count,
				     writable ? FOLL_WRITE : 0,
				     buffer->pages);
	if (pinned != page_count) {
		if (pinned > 0) {
			buffer->page_count = pinned;
			onekvm_offload_unpin_user_buffer(buffer);
		}
		return pinned < 0 ? pinned : -EFAULT;
	}

	buffer->page_count = page_count;
	buffer->writable = writable;
	sg_init_table(buffer->scatterlist, page_count);
	for (index = 0; index < page_count; index++) {
		count = min_t(unsigned int, remaining,
				  PAGE_SIZE - page_offset);
		sg_set_page(&buffer->scatterlist[index], buffer->pages[index],
			    count, page_offset);
		remaining -= count;
		page_offset = 0;
	}
	return 0;
}

static void onekvm_offload_release_batch_pins(
	struct onekvm_offload_batch_pins *pins)
{
	unsigned int index;

	for (index = 0; index < pins->count; index++) {
		set_page_dirty_lock(pins->pages[index].page);
		unpin_user_page(pins->pages[index].page);
	}
	memset(pins->pages, 0,
	       pins->count * sizeof(struct onekvm_offload_batch_page));
	pins->count = 0;
}

static int onekvm_offload_pin_batch_buffer(
	struct onekvm_offload_user_buffer *buffer, u64 pointer, size_t length,
	struct onekvm_offload_batch_pins *pins)
{
	unsigned long address;
	unsigned long user_page;
	unsigned int page_offset;
	unsigned int page_count;
	unsigned int page_index;
	unsigned int cache_index;
	unsigned int count;
	unsigned int remaining = length;
	struct page *page;
	long pinned;

	memset(buffer, 0, sizeof(*buffer));
	if (!length)
		return 0;
	if (pointer > ULONG_MAX)
		return -EFAULT;
	address = (unsigned long)pointer;
	if (length > ULONG_MAX - address)
		return -EFAULT;
	page_offset = offset_in_page(address);
	page_count = DIV_ROUND_UP(page_offset + length, PAGE_SIZE);
	if (page_count > ONEKVM_OFFLOAD_MAX_PAGES)
		return -EMSGSIZE;
	user_page = address & PAGE_MASK;
	buffer->page_count = page_count;
	sg_init_table(buffer->scatterlist, page_count);
	for (page_index = 0; page_index < page_count; page_index++) {
		page = NULL;
		for (cache_index = 0; cache_index < pins->count;
		     cache_index++) {
			if (pins->pages[cache_index].user_address == user_page) {
				page = pins->pages[cache_index].page;
				break;
			}
		}
		if (!page) {
			pinned = pin_user_pages_fast(user_page, 1, FOLL_WRITE,
						     &page);
			if (pinned != 1)
				return pinned < 0 ? pinned : -EFAULT;
			pins->pages[pins->count].user_address = user_page;
			pins->pages[pins->count].page = page;
			pins->count++;
		}
		buffer->pages[page_index] = page;
		count = min_t(unsigned int, remaining,
				  PAGE_SIZE - page_offset);
		sg_set_page(&buffer->scatterlist[page_index], page, count,
			    page_offset);
		remaining -= count;
		page_offset = 0;
		user_page += PAGE_SIZE;
	}
	return 0;
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

static int onekvm_offload_finish_gcm(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *parameters,
	struct scatterlist *ciphertext)
{
	void __user *aad_user =
		(void __user *)(uintptr_t)parameters->aad_ptr;
	void __user *dst_user =
		(void __user *)(uintptr_t)parameters->dst_ptr;
	u8 counter[AES_BLOCK_SIZE];
	u8 tag_mask[AES_BLOCK_SIZE];
	u8 tag[AES_BLOCK_SIZE];
	unsigned int index;
	int error;

	if (parameters->aad_len &&
	    copy_from_user(context->input, aad_user, parameters->aad_len))
		return -EFAULT;
	memcpy(counter, parameters->iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
	put_unaligned_be32(1, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
	crypto_cipher_encrypt_one(context->aes, tag_mask, counter);
	error = onekvm_offload_ghash(context, context->input,
		parameters->aad_len, ciphertext, parameters->data_len, tag);
	if (error)
		goto clear_temporary;
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

static int onekvm_offload_encrypt_parameters(
	struct onekvm_offload_context *context,
	const struct onekvm_offload_encrypt_request *request,
	struct onekvm_offload_user_buffer *prepared_in_place)
{
	struct onekvm_offload_encrypt_request parameters = *request;
	struct onekvm_offload_user_buffer source_buffer = { };
	struct onekvm_offload_user_buffer destination_buffer = { };
	struct scatterlist *source_scatterlist;
	struct scatterlist *destination_scatterlist;
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
	if (prepared_in_place) {
		if (parameters.data_len && !in_place)
			return -EINVAL;
		source_scatterlist = prepared_in_place->scatterlist;
		destination_scatterlist = prepared_in_place->scatterlist;
	} else {
		error = onekvm_offload_pin_user_buffer(&destination_buffer,
						       parameters.dst_ptr,
						       parameters.data_len, true);
		if (error)
			return error;
		if (in_place) {
			source_scatterlist = destination_buffer.scatterlist;
		} else {
			error = onekvm_offload_pin_user_buffer(&source_buffer,
							       parameters.src_ptr,
							       parameters.data_len,
							       false);
			if (error)
				goto unpin_destination;
			source_scatterlist = source_buffer.scatterlist;
		}
		destination_scatterlist = destination_buffer.scatterlist;
	}

	memcpy(counter, parameters.iv, ONEKVM_OFFLOAD_GCM_IV_SIZE);
	put_unaligned_be32(2, counter + ONEKVM_OFFLOAD_GCM_IV_SIZE);
	started_ns = ktime_get_ns();
	if (parameters.data_len) {
		error = cvitek_spacc_aes_ctr_encrypt_sg(
			source_scatterlist, destination_scatterlist,
			parameters.data_len, context->key, context->key_len,
			counter);
		if (error)
			goto clear_temporary;
	}
	error = onekvm_offload_finish_gcm(context, &parameters,
		 destination_scatterlist);
	if (error)
		goto clear_temporary;
	atomic64_add(ktime_get_ns() - started_ns, &offload_crypto_ns);
clear_temporary:
	memzero_explicit(counter, sizeof(counter));
	if (!prepared_in_place && !in_place)
		onekvm_offload_unpin_user_buffer(&source_buffer);
unpin_destination:
	if (!prepared_in_place)
		onekvm_offload_unpin_user_buffer(&destination_buffer);
	return error;
}

static int onekvm_offload_encrypt(struct onekvm_offload_context *context,
				  void __user *argument)
{
	struct onekvm_offload_encrypt_request parameters;

	if (copy_from_user(&parameters, argument, sizeof(parameters)))
		return -EFAULT;
	return onekvm_offload_encrypt_parameters(context, &parameters, NULL);
}

static int onekvm_offload_encrypt_batch(
	struct onekvm_offload_context *context, void __user *argument)
{
	struct onekvm_offload_encrypt_request *requests;
	struct onekvm_offload_batch_request batch;
	struct onekvm_offload_batch_pins pins = { };
	void __user *requests_user;
	size_t requests_size;
	unsigned int index;
	bool deduplicate_pages = deduplicate_batch_pages;
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
		if (requests[index].data_len &&
		    requests[index].src_ptr != requests[index].dst_ptr)
			deduplicate_pages = false;
	}
	if (deduplicate_pages) {
		if (!context->batch_buffers)
			context->batch_buffers = kvcalloc(
				ONEKVM_OFFLOAD_MAX_BATCH,
				sizeof(*context->batch_buffers), GFP_KERNEL);
		if (!context->batch_pages)
			context->batch_pages = kvcalloc(
				ONEKVM_OFFLOAD_MAX_BATCH *
					ONEKVM_OFFLOAD_MAX_PAGES,
				sizeof(*context->batch_pages), GFP_KERNEL);
		if (!context->batch_buffers || !context->batch_pages) {
			error = -ENOMEM;
			goto complete;
		}
		pins.pages = context->batch_pages;
		for (index = 0; index < batch.count; index++) {
			error = onekvm_offload_pin_batch_buffer(
				&context->batch_buffers[index],
				requests[index].dst_ptr,
				requests[index].data_len, &pins);
			if (error)
				goto release_pins;
		}
	}

	for (index = 0; index < batch.count; index++) {
		error = onekvm_offload_encrypt_parameters(context,
			&requests[index], deduplicate_pages ?
				&context->batch_buffers[index] : NULL);
		if (error)
			break;
		batch.completed++;
	}
	atomic64_inc(&offload_batch_calls);
	atomic64_add(batch.completed, &offload_batch_packets);
	if (deduplicate_pages)
		atomic64_add(pins.count, &offload_batch_unique_pages);

release_pins:
	if (pins.pages)
		onekvm_offload_release_batch_pins(&pins);
	if (deduplicate_pages && context->batch_buffers)
		memset(context->batch_buffers, 0,
		       batch.count * sizeof(*context->batch_buffers));
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
	if (!context->input) {
		kfree(context->input);
		kfree(context);
		return -ENOMEM;
	}
	mutex_init(&context->lock);
	file->private_data = context;
	return 0;
}

static int onekvm_offload_release(struct inode *inode, struct file *file)
{
	struct onekvm_offload_context *context = file->private_data;

	if (!context)
		return 0;
	mutex_lock(&context->lock);
	onekvm_offload_free_crypto(context);
	kvfree(context->batch_pages);
	kvfree(context->batch_buffers);
	memzero_explicit(context->input, ONEKVM_OFFLOAD_MAX_INPUT +
			 ONEKVM_OFFLOAD_GCM_TAG_SIZE);
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
	&dev_attr_driver.attr,
	NULL,
};
ATTRIBUTE_GROUPS(onekvm_offload);

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
		error = -ENODEV;
		goto unregister_spacc;
	}
	error = misc_register(&onekvm_offload_device);
	if (error)
		goto unregister_spacc;
	error = sysfs_create_groups(&onekvm_offload_device.this_device->kobj,
				   onekvm_offload_groups);
	if (error) {
		misc_deregister(&onekvm_offload_device);
		goto unregister_spacc;
	}
	pr_info("OneKVM crypto offload ABI v%u registered\n",
		ONEKVM_OFFLOAD_ABI_VERSION);
	return 0;

unregister_spacc:
	if (onekvm_spacc_platform_device) {
		platform_device_unregister(onekvm_spacc_platform_device);
		onekvm_spacc_platform_device = NULL;
	}
	return error;
}

static void __exit onekvm_offload_exit(void)
{
	sysfs_remove_groups(&onekvm_offload_device.this_device->kobj,
			    onekvm_offload_groups);
	misc_deregister(&onekvm_offload_device);
	if (onekvm_spacc_platform_device) {
		platform_device_unregister(onekvm_spacc_platform_device);
		onekvm_spacc_platform_device = NULL;
	}
}

module_init(onekvm_offload_init);
module_exit(onekvm_offload_exit);

MODULE_DESCRIPTION("OneKVM AES-GCM userspace TX offload ABI");
MODULE_AUTHOR("OneKVM");
MODULE_LICENSE("GPL");
