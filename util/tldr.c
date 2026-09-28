/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TL;DR: Thrifty Live Data Recorder
 *
 * Copyright (C) 2026 Red Hat Inc.
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "util/tldr-internal.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "qapi/error.h"

struct QTLDRConfig {
    Object parent;

    char *crash_target;
};

static int qtldr_active;
static char *qtldr_crash_target;

#define TYPE_QTLDR_CONFIG "tldr-config"

OBJECT_DECLARE_SIMPLE_TYPE(QTLDRConfig, QTLDR_CONFIG);

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(QTLDRConfig,
                                          qtldr_config,
                                          QTLDR_CONFIG,
                                          OBJECT,
                                          { TYPE_USER_CREATABLE },
                                          { NULL });


static void
qtldr_config_finalize(Object *obj)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);

    g_free(cfg->crash_target);
}


static char *
qtldr_config_get_crash_target(Object *obj, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);
    return g_strdup(cfg->crash_target);
}


static void
qtldr_config_set_crash_target(Object *obj, const char *path, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);
    g_free(cfg->crash_target);
    cfg->crash_target = g_strdup(path);
}


static void
qtldr_config_complete(UserCreatable *uc, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(uc);

    /*
     * Forbid changes, since once configured, we can't safely
     * change it due to signal handlers running without ability
     * to hold mutex locks
     */
    if (qtldr_crash_target) {
        error_setg(errp, "TLDR configuration cannot be changed");
        return;
    }

    qatomic_store_release(&qtldr_crash_target, g_strdup(cfg->crash_target));
    qatomic_inc(&qtldr_active);
}


static bool
qtldr_config_prepare_delete(UserCreatable *uc, Error **errp)
{
    /*
     * Forbid deletion, since once configured, we can't safely
     * change it due to signal handlers running without ability
     * to hold mutex locks
     */
    error_setg(errp, "Deleting the 'tldr-config' object is not supported");
    return false;
}


static void
qtldr_config_class_init(ObjectClass *klass, const void *opaque)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(klass);
    object_class_property_add_str(klass, "crash-target",
                                  qtldr_config_get_crash_target,
                                  qtldr_config_set_crash_target);

    ucc->complete = qtldr_config_complete;
    ucc->prepare_delete = qtldr_config_prepare_delete;
}


static void
qtldr_config_init(Object *obj)
{
}


/*
 * WARNING: Code below this marker is used when dumping
 * WARNING: the data recorder buffers. It is subject to
 * WARNING: execution directly in signal handler context
 * WARNING: on a limited stack (SIGSTKSZ).
 *
 * WARNING: Thus from here onwards must only use async
 * WARNING: signal safe POSIX functions.
 */


static void
qtldr_write_int_buf(int fd, uint64_t v,
                    const char *digits, size_t digitslen,
                    char *target, size_t targetlen)
{
    size_t offset = targetlen;
    do {
        uint64_t r = (v % digitslen);
        target[--offset] = digits[r];
        v /= digitslen;
    } while (v && offset);
    ignore_value(write(fd, target + offset, targetlen - offset));
}


static void
qtldr_write_int_dec(int fd, uint64_t v)
{
    static char digits[] = "0123456789";
    char target[20];
    qtldr_write_int_buf(fd, v, digits, strlen(digits),
                        target, G_N_ELEMENTS(target));
}


static void
qtldr_write_int_hex(int fd, uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    char target[16];
    qtldr_write_int_buf(fd, v, digits, strlen(digits),
                        target, G_N_ELEMENTS(target));
}


static const char *
qtldr_crash_dump_signal_str(int signo)
{
    switch (signo) {
    case SIGSEGV:
        return "SIGSEGV";
#ifndef WIN32
    case SIGBUS:
        return "SIGBUS";
#endif
    case SIGABRT:
        return "SIGABRT";
    case SIGILL:
        return "SIGILL";
    case SIGFPE:
        return "SIGFPE";
    }
    return NULL;
}


static const char *
qtldr_crash_dump_code_str(int signo, int code)
{
    switch (code) {
#ifdef SI_USER
    case SI_USER:
        return "User process kill";
#endif
#ifdef SI_KERNEL
    case SI_KERNEL:
        return "Kernel process kill";
#endif
#ifdef SI_QUEUE
    case SI_QUEUE:
        return "Signal queue";
#endif
#ifdef SI_TIMER
    case SI_TIMER:
        return "Timer expired";
#endif
#ifdef SI_MESGQ
    case SI_MESGQ:
        return "Message queue state changed";
#endif
#ifdef SI_ASYNCIO
    case SI_ASYNCIO:
        return "AIO completed";
#endif
#ifdef SI_TKILL
    case SI_TKILL:
        return "User thread kill";
#endif
    }
    switch (signo) {
    case SIGSEGV:
        switch (code) {
#ifdef SEGV_MAPERR
        case SEGV_MAPERR:
            return "Address not mapped";
#endif
#ifdef SEGV_ACCERR
        case SEGV_ACCERR:
            return "Access permissions";
#endif
#ifdef SEGV_BNDERR
        case SEGV_BNDERR:
            return "Address out of bounds";
#endif
#ifdef SEGV_PKUERR
        case SEGV_PKUERR:
            return "Memory protection keys";
#endif
        }
        break;

#ifndef WIN32
    case SIGBUS:
        switch (code) {
#ifdef BUS_ADRALN
        case BUS_ADRALN:
            return "Address alignment";
#endif
#ifdef BUS_ADDRER
        case BUS_ADRERR:
            return "Physical address error";
#endif
#ifdef BUS_OBJERR
        case BUS_OBJERR:
            return "Object hardware error";
#endif
#ifdef BUS_MCEERR_AR
        case BUS_MCEERR_AR:
            return "Memory error, machine check";
#endif
#ifdef BUS_MCEERR_AO
        case BUS_MCEERR_AO:
            return "Memory error, not consumed";
#endif
        }
        break;
#endif

    case SIGILL:
        switch (code) {
#ifdef ILL_ILLOPC
        case ILL_ILLOPC:
            return "Illegal opcode";
#endif
#ifdef ILL_ILLOPN
        case ILL_ILLOPN:
            return "Illegal operand";
#endif
#ifdef ILL_ILLADR
        case ILL_ILLADR:
            return "Illegal addressing mode";
#endif
#ifdef ILL_ILLTRP
        case ILL_ILLTRP:
            return "Illegal trap";
#endif
#ifdef ILL_PRVOPC
        case ILL_PRVOPC:
            return "Privileged opcode";
#endif
#ifdef ILL_PRVREG
        case ILL_PRVREG:
            return "Privileged register";
#endif
#ifdef ILL_COPROC
        case ILL_COPROC:
            return "Coprocessor error";
#endif
#ifdef ILL_BADSTK
        case ILL_BADSTK:
            return "Internal stack error";
#endif
        }
        break;

    case SIGFPE:
        switch (code) {
#ifdef FPE_INTDIV
        case FPE_INTDIV:
            return "Integer divide by zero";
#endif
#ifdef FPE_INTOVF
        case FPE_INTOVF:
            return "Integer overflow";
#endif
#ifdef FPE_FLTDIV
        case FPE_FLTDIV:
            return "Floating-point divide by zero";
#endif
#ifdef FPE_FLTOVF
        case FPE_FLTOVF:
            return "Floating-point overflow";
#endif
#ifdef FPE_FLTUND
        case FPE_FLTUND:
            return "Floating-point underflow";
#endif
#ifdef FPE_FLTRES
        case FPE_FLTRES:
            return "Floating-point inexact result";
#endif
#ifdef FPE_FLTINV
        case FPE_FLTINV:
            return "Floating-point invalid operation";
#endif
#ifdef FPE_FLTSUB
        case FPE_FLTSUB:
            return "Subscript out of range";
#endif
        }
        break;
    }
    return NULL;
}


static void
qtldr_crash_dump_print_field(int fd, const char *label,
                             const char *valstr, int val)
{
    ignore_value(write(fd, label, strlen(label)));
    if (valstr) {
        ignore_value(write(fd, valstr, strlen(valstr)));
        ignore_value(write(fd, " (", 2));
    }
    qtldr_write_int_dec(fd, val);
    if (valstr) {
        ignore_value(write(fd, ")", 1));
    }
    ignore_value(write(fd, "\n", 1));
}


static void
qtldr_crash_dump_print_siginfo(int fd, siginfo_t *si)
{
    const char *signostr = qtldr_crash_dump_signal_str(si->si_signo);
    const char *codestr = qtldr_crash_dump_code_str(si->si_signo, si->si_code);
    ignore_value(write(fd, QTLDR_DUMP_TRIGGER_PREFIX,
                       strlen(QTLDR_DUMP_TRIGGER_PREFIX)));
    ignore_value(write(fd, "\n", 1));

    qtldr_crash_dump_print_field(fd, "  - Signal: ", signostr, si->si_signo);
    qtldr_crash_dump_print_field(fd, "  - Code: ", codestr, si->si_code);

    ignore_value(write(fd, "  - Address: 0x", 15));
    qtldr_write_int_hex(fd, (uint64_t)si->si_addr);
    ignore_value(write(fd, "\n", 1));
}


void
qtldr_crash_dump_internal(int fd, siginfo_t *si)
{
    if (fd == -1) {
        fd = STDERR_FILENO;
    }

    ignore_value(write(fd, QTLDR_DUMP_LEADER, strlen(QTLDR_DUMP_LEADER)));
    if (si) {
        qtldr_crash_dump_print_siginfo(fd, si);
    } else {
        ignore_value(write(fd, QTLDR_DUMP_TRIGGER_PREFIX,
                           strlen(QTLDR_DUMP_TRIGGER_PREFIX)));
        ignore_value(write(fd, "manual\n", 7));
    }

    ignore_value(write(fd, QTLDR_DUMP_TRAILER, strlen(QTLDR_DUMP_TRAILER)));
}


void
qtldr_crash_dump_signal(siginfo_t *si)
{
    int fd = STDERR_FILENO;
    const char *tgt;

    if (!qatomic_read(&qtldr_active)) {
        return;
    }

    tgt = qatomic_load_acquire(&qtldr_crash_target);
    if (tgt) {
        /*
         * Must NOT use qemu_create, as it is not safe from
         * signal handler context due to using monitor APIs
         */
        fd = open(tgt, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            /*
             * Couldn't open our designated crash report
             * file location, so fallback to STDERR as
             * the least worst next best option, and
             * warn the user of the failure
             */
            fd = STDERR_FILENO;
            int saved_errno = errno;
            ignore_value(write(fd, QTLDR_DUMP_OPEN_ERROR,
                               strlen(QTLDR_DUMP_OPEN_ERROR)));
            ignore_value(write(fd, tgt, strlen(tgt)));
            ignore_value(write(fd, "': ", 3));
            qtldr_write_int_dec(fd, saved_errno);
            ignore_value(write(fd, "\n", 1));
        }
    }

    qtldr_crash_dump_internal(fd, si);

    if (fd != STDERR_FILENO) {
        qemu_fdatasync(fd);
        close(fd);
    }
}
