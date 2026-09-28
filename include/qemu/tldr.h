/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TL;DR: Thrifty Live Data Recorder
 *
 * Copyright (C) 2026 Red Hat Inc.
 */

#ifndef QEMU_TLDR_H__
#define QEMU_TLDR_H__

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
