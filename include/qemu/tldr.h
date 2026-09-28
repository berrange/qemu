/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TL;DR: Thrifty Live Data Recorder
 *
 * Copyright (C) 2026 Red Hat Inc.
 */

#ifndef QEMU_TLDR_H__
#define QEMU_TLDR_H__

#include "qapi/qapi-types-tldr.h"

extern unsigned int qtldr_msg_enabled_mask;

/**
 * qtldr_msg_enabled:
 * @bucket: bucket to check status for
 *
 * Returns: true if @bucket is enabled for recording
 */
#define qtldr_msg_enabled(bucket) \
    (qtldr_msg_enabled_mask & (1 << bucket))

/**
 * qtldr_msg_record:
 * @bucket: bucket to record into
 * @msg: the message text to record
 *
 * Records @msg into @bucket, potentially overwriting
 * old messages if the capacity is at its maximum
 */
void qtldr_msg_record(QTLDRMsgBucketType bucket,
                      const char *msg);

/**
 * qtldr_msg_record_printf:
 * @bucket: bucket to record into
 * @fmt: the message format string to record
 * @...: the arguments for @fmt
 *
 * Formats @fmt as a printf string and records the
 * result into @bucket, potentially overwriting
 * old messages if the capacity is at its maximum
 */
void qtldr_msg_record_printf(QTLDRMsgBucketType bucket,
                             const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

/**
 * qtldr_msg_record_vprintf:
 * @bucket: bucket to record into
 * @fmt: the message format string to record
 * @ap: the arguments for @fmt
 *
 * Formats @fmt as a printf string and records the
 * result into @bucket, potentially overwriting
 * old messages if the capacity is at its maximum
 */
void qtldr_msg_record_vprintf(QTLDRMsgBucketType bucket,
                              const char *fmt, va_list ap)
    G_GNUC_PRINTF(2, 0);

/**
 * qtldr_crash_dump_signal:
 * @si: signal information
 *
 * Print a crash dump in response to a signal.
 *
 * The crash will be printed to the configured crash
 * file, if set. If opening the crash file fails, or
 * no path is configured, STDERR will be used.
 */
void qtldr_crash_dump_signal(siginfo_t *si);

#endif /* QEMU_TLDR_H__ */
