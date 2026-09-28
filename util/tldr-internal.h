/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TL;DR: Thrifty Live Data Recorder
 *
 * Copyright (C) 2026 Red Hat Inc.
 */

#ifndef QEMU_TLDR_INTERNAL_H__
#define QEMU_TLDR_INTERNAL_H__

#include "qemu/tldr.h"

#define QTLDR_DUMP_LEADER "\n🚨🚨🚨 QEMU Data Recorder Start 🚨🚨🚨\n"
#define QTLDR_DUMP_TRAILER "\n🚨🚨🚨 QEMU Data Recorder End 🚨🚨🚨\n\n"
#define QTLDR_DUMP_TRIGGER_PREFIX "\n🔍 Trigger:"
#define QTLDR_DUMP_MSG_BUCKET_PREFIX "\n🎥  Message recording '"
#define QTLDR_DUMP_OPEN_ERROR "🔥 Unable to dump to '"

/*
 * All writes to this struct must be protected by
 * the qtldr_lock. Reads and writes of 'allocated'
 * and 'next' must also use atomics, since they
 * are accessed without locks during signal handler
 * dumps. Reads of 'buf' may be done without locks
 * or atomics, since we're happy to dump whatever
 * incomplete writes may be in progress.
 */
typedef struct {
    char *buf;
    size_t allocated; /* Currently allocated */
    size_t capacity; /* Max permitted allocation */
    size_t next; /* Offset to write next byte */
} QTLDRMsgBucket;

#define QTLDR_MSG_ENTRY_MAX_BYTES (2 * 1024)
#define QTLDR_MSG_BUCKET_SIZE_BYTES (64 * 1024)

/*
 * MUST always be greater than entry size, otherwise
 * wrapping logic doesn't work
 */
G_STATIC_ASSERT(QTLDR_MSG_BUCKET_SIZE_BYTES >
                QTLDR_MSG_ENTRY_MAX_BYTES);

extern QTLDRMsgBucket qtldr_msg_buckets[];

extern char *(*qtldr_now_str_func)(void);

void qtldr_crash_dump_internal(int fd, siginfo_t *si);

#endif /* QEMU_TLDR_INTERNAL_H__ */
