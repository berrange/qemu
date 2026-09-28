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
#define QTLDR_DUMP_OPEN_ERROR "🔥 Unable to dump to '"

void qtldr_crash_dump_internal(int fd, siginfo_t *si);

#endif /* QEMU_TLDR_INTERNAL_H__ */
