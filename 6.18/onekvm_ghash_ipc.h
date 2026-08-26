/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ONEKVM_GHASH_IPC_H
#define ONEKVM_GHASH_IPC_H

#include <linux/stddef.h>
#include <linux/types.h>

#define ONEKVM_GHASH_SHM_PHYS 0x8FFE0000UL
#define ONEKVM_GHASH_SHM_SIZE 0x00010000UL
#define ONEKVM_GHASH_SHM_MAGIC 0x54524847U /* 'GHRT' */
#define ONEKVM_GHASH_SHM_VERSION 1U
#define ONEKVM_GHASH_MAX_REQUESTS 128U
#define ONEKVM_GHASH_FLAG_READY (1U << 0)

struct onekvm_ghash_request {
	u32 aad_offset;
	u32 aad_length;
	u32 data_offset;
	u32 data_length;
	u8 tag[16];
};

#define ONEKVM_GHASH_HEADER_SIZE 96U
#define ONEKVM_GHASH_REQUESTS_SIZE \
	(sizeof(struct onekvm_ghash_request) * ONEKVM_GHASH_MAX_REQUESTS)
#define ONEKVM_GHASH_PAYLOAD_SIZE \
	(ONEKVM_GHASH_SHM_SIZE - ONEKVM_GHASH_HEADER_SIZE - \
	 ONEKVM_GHASH_REQUESTS_SIZE)

struct onekvm_ghash_shm {
	u32 magic;
	u32 version;
	u32 size;
	u32 flags;
	u32 seq;
	u32 ack;
	s32 status;
	u32 count;
	u32 payload_used;
	u32 max_requests;
	u8 hash_subkey[16];
	u32 reserved[2];
	u64 jobs;
	u64 packets;
	u64 ticks;
	u64 errors;
	struct onekvm_ghash_request requests[ONEKVM_GHASH_MAX_REQUESTS];
	u8 payload[ONEKVM_GHASH_PAYLOAD_SIZE];
};

static_assert(sizeof(struct onekvm_ghash_request) == 32);
static_assert(offsetof(struct onekvm_ghash_shm, requests) ==
	      ONEKVM_GHASH_HEADER_SIZE);
static_assert(sizeof(struct onekvm_ghash_shm) == ONEKVM_GHASH_SHM_SIZE);

#endif
