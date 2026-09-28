/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TL;DR: Thrifty Live Data Recorder
 *
 * Copyright (C) 2026 Red Hat Inc.
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "util/tldr-internal.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-tldr.h"
#include "qapi/qapi-visit-tldr.h"

struct QTLDRConfig {
    Object parent;

    char *crash_target;
    QTLDRMsgBucketConfigList *messages;
};

static QemuMutex qtldr_lock;
static int qtldr_active;
static char *qtldr_crash_target;
QTLDRMsgBucket qtldr_msg_buckets[QTLDR_MSG_BUCKET_TYPE__MAX];
unsigned int qtldr_msg_enabled_mask;

#define TYPE_QTLDR_CONFIG "tldr-config"

OBJECT_DECLARE_SIMPLE_TYPE(QTLDRConfig, QTLDR_CONFIG);

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(QTLDRConfig,
                                          qtldr_config,
                                          QTLDR_CONFIG,
                                          OBJECT,
                                          { TYPE_USER_CREATABLE },
                                          { NULL });

static char *
qtldr_now_str_func_default(void)
{
    g_autoptr(GDateTime) dt = g_date_time_new_now_utc();
    return g_date_time_format_iso8601(dt);
}

char *(*qtldr_now_str_func)(void) = qtldr_now_str_func_default;


static void __attribute__((constructor))
qtldr_global_init(void)
{
    qemu_mutex_init(&qtldr_lock);
}


static void
qtldr_config_finalize(Object *obj)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);

    g_free(cfg->crash_target);
    qapi_free_QTLDRMsgBucketConfigList(cfg->messages);
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

static void qtldr_config_get_messages(Object *obj, Visitor *v, const char *name,
                                      void *opaque, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);

    visit_type_QTLDRMsgBucketConfigList(v, name, &cfg->messages, errp);
}

static void qtldr_config_set_messages(Object *obj, Visitor *v, const char *name,
                                      void *opaque, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(obj);
    QTLDRMsgBucketConfigList *oldmsgs;

    oldmsgs = cfg->messages;
    visit_type_QTLDRMsgBucketConfigList(v, name, &cfg->messages, errp);

    qapi_free_QTLDRMsgBucketConfigList(oldmsgs);
}

static void
qtldr_config_complete(UserCreatable *uc, Error **errp)
{
    QTLDRConfig *cfg = QTLDR_CONFIG(uc);
    QTLDRMsgBucketConfigList *messages = cfg->messages;

    /*
     * Forbid changes, since once configured, we can't safely
     * change it due to signal handlers running without ability
     * to hold mutex locks
     */
    if (qtldr_crash_target || qtldr_msg_enabled_mask) {
        error_setg(errp, "TLDR configuration cannot be changed");
        return;
    }

    /*
     * Sanity check before changing anything, so errors don't
     * leave us in a partially configured state
     */
    while (messages) {
        QTLDRMsgBucketConfig *msgcfg = messages->value;
        assert(msgcfg->type < QTLDR_MSG_BUCKET_TYPE__MAX);

        if (msgcfg->has_capacity &&
            msgcfg->capacity <= QTLDR_MSG_ENTRY_MAX_BYTES) {
            error_setg(errp, "Message bucket capacity must be greater than %d",
                       QTLDR_MSG_ENTRY_MAX_BYTES);
            return;
        }
        messages = messages->next;
    }

    qemu_mutex_lock(&qtldr_lock);
    qatomic_store_release(&qtldr_crash_target, g_strdup(cfg->crash_target));

    messages = cfg->messages;
    while (messages) {
        QTLDRMsgBucketConfig *msgcfg = messages->value;
        assert(msgcfg->type < QTLDR_MSG_BUCKET_TYPE__MAX);

        if (msgcfg->has_capacity) {
            qtldr_msg_buckets[msgcfg->type].capacity = msgcfg->capacity;
        } else {
            qtldr_msg_buckets[msgcfg->type].capacity =
                QTLDR_MSG_BUCKET_SIZE_BYTES;
        }

        qtldr_msg_enabled_mask |= (1 << msgcfg->type);

        messages = messages->next;
    }

    if (!cfg->messages) {
        size_t i;
        qtldr_msg_enabled_mask =
            (1 << QTLDR_MSG_BUCKET_TYPE_ERROR) |
            (1 << QTLDR_MSG_BUCKET_TYPE_COMMAND) |
            (1 << QTLDR_MSG_BUCKET_TYPE_EVENT) |
            (1 << QTLDR_MSG_BUCKET_TYPE_LOG);
        for (i = 0; i < QTLDR_MSG_BUCKET_TYPE__MAX; i++) {
            qtldr_msg_buckets[i].capacity = QTLDR_MSG_BUCKET_SIZE_BYTES;
        }
    }

    qatomic_inc(&qtldr_active);
    qemu_mutex_unlock(&qtldr_lock);
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
    object_class_property_add(klass, "messages", "QTLDRMsgBucketConfigList",
                              qtldr_config_get_messages,
                              qtldr_config_set_messages,
                              NULL, NULL);

    ucc->complete = qtldr_config_complete;
    ucc->prepare_delete = qtldr_config_prepare_delete;
}


static void
qtldr_config_init(Object *obj)
{
}


/*
 * WARNING: The data recorder is intended to be called from
 * WARNING: many places within QEMU, including tracing, error
 * WARNING: reporting and logging code.
 *
 * WARNING: The code following this marker is used in the call
 * WARNING: chain from qtldr_msg_record() and must be self
 * WARNING: contained and performance oriented.
 */

static void
qtldr_msg_record_ensure_size(QTLDRMsgBucket *bucket,
                             size_t need)
{
    /*
     * If bucket is not yet at max size then we can't have
     * wrapped the buffer and so 'head' must reflect the
     * amount of written data so far.
     */
    if (bucket->allocated < bucket->capacity) {
        size_t space = bucket->allocated - bucket->next;
        if (space < need) {
            size_t newlen = MIN(bucket->capacity,
                                bucket->allocated + MAX(4096, need - space));
            bucket->buf = g_realloc(bucket->buf, newlen);
            /*
             * Fill with zeros, so the dumping method
             * knows what is unused so far.
             */
            memset(bucket->buf + bucket->allocated, '\0',
                   newlen - bucket->allocated);
            qatomic_store_release(&bucket->allocated, newlen);
        }
    }
}


static size_t
qtldr_msg_record_append_buf(QTLDRMsgBucket *bucket,
                            size_t next,
                            const void *buf,
                            size_t len)
{
    size_t forend = MIN(bucket->allocated - next, len);
    size_t forfront = len - forend;

    if (forend) {
        memcpy(bucket->buf + next, buf, forend);
    }
    if (forfront) {
        memcpy(bucket->buf, buf + forend, forfront);
        return forfront;
    } else {
        return (next + forend) % bucket->allocated;
    }
}


void
qtldr_msg_record(QTLDRMsgBucketType type,
                 const char *msg)
{
    QTLDRMsgBucket *bucket;
    size_t msglen, timelen;
    g_autofree char *timestr = qtldr_now_str_func();
    bool addnl = false;
    uint16_t recordlen;
    size_t next;

    assert(type < QTLDR_MSG_BUCKET_TYPE__MAX);
    if (!qtldr_msg_enabled(type)) {
        return;
    }

    qemu_mutex_lock(&qtldr_lock);

    bucket = &qtldr_msg_buckets[type];
    timelen = strlen(timestr);
    msglen = strlen(msg);

    recordlen = timelen + 1 /* " " */ + msglen;
    if (recordlen > (QTLDR_MSG_ENTRY_MAX_BYTES - 1)) {
        size_t cut = (QTLDR_MSG_ENTRY_MAX_BYTES - 1)  - recordlen;
        msglen -= cut;
        recordlen -= cut;
    }

    if (msglen && msg[msglen - 1] != '\n') {
        addnl = true;
        recordlen++;
    }


    qtldr_msg_record_ensure_size(bucket, recordlen);
    next = qtldr_msg_record_append_buf(bucket, bucket->next, timestr, timelen);
    next = qtldr_msg_record_append_buf(bucket, next, " ", 1);
    next = qtldr_msg_record_append_buf(bucket, next, msg, msglen);
    if (addnl) {
        next = qtldr_msg_record_append_buf(bucket, next, "\n", 1);
    }

    /*
     * We could be racing with a signal handler dumping text
     * outside the mutex lock, so while we write text without
     * any sync, we atomically change the "next" pointer.
     *
     * Worst case, some text the signal handler dumps will be
     * "new" instead of old part of the buffer.
     */
    qatomic_store_release(&bucket->next, next);
    qemu_mutex_unlock(&qtldr_lock);
}


void
qtldr_msg_record_printf(QTLDRMsgBucketType type,
                        const char *fmt, ...)
{
    char msg[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, G_N_ELEMENTS(msg), fmt, ap);
    va_end(ap);

    qtldr_msg_record(type, msg);
}


void
qtldr_msg_record_vprintf(QTLDRMsgBucketType type,
                         const char *fmt, va_list ap)
{
    char msg[1024];
    vsnprintf(msg, G_N_ELEMENTS(msg), fmt, ap);
    qtldr_msg_record(type, msg);
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


static void
qtldr_crash_dump_msg(int fd, QTLDRMsgBucketType type, QTLDRMsgBucket *bucket)
{
    size_t allocated, head;

    if (!bucket->allocated) {
        return;
    }
    ignore_value(write(fd, QTLDR_DUMP_MSG_BUCKET_PREFIX,
                       strlen(QTLDR_DUMP_MSG_BUCKET_PREFIX)));
    ignore_value(write(fd, QTLDRMsgBucketType_str(type),
                       strlen(QTLDRMsgBucketType_str(type))));
    ignore_value(write(fd, "':\n", 3));

    /*
     * We're potentially racing with a thread appending.
     * Load 'head' first, so we're guaranteed it does
     * not point beyond the 'allocated' region, should
     * we be racing with buffer enlargement
     */
    head = qatomic_load_acquire(&bucket->next);
    allocated = qatomic_load_acquire(&bucket->allocated);

    /*
     * If we haven't wrapped around yet, the allocated but
     * unused space is filled with NULs. We can assume
     * that no valid messages contain NULs, since we used
     * "strlen" when writing messages originally.
     */
    if (bucket->buf[head] != '\0') {
        ignore_value(write(fd, bucket->buf + head,
                           allocated - head));
    }
    ignore_value(write(fd, bucket->buf, head));
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
    size_t i;

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

    for (i = 0; i < QTLDR_MSG_BUCKET_TYPE__MAX; i++) {
        qtldr_crash_dump_msg(fd, i, &qtldr_msg_buckets[i]);
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


/*
 * WARNING: Code below this marker provides a QMP handler
 * WARNING: for use in normal execution. It calls into
 * WARNING: the common crash report outputting APIs, but
 * WARNING: this specific method is not restricted to async
 * WARNING: signal safe POSIX functions.
 */


void
qmp_tldr_dump(const char *target, Error **errp)
{
    int fd;

    if (!qatomic_read(&qtldr_active)) {
        error_setg(errp, "No 'tldr-config' object has been creted");
        return;
    }

    fd = qemu_create(target, O_WRONLY | O_TRUNC, 0600, errp);
    if (fd < 0) {
        return;
    }

    qemu_mutex_lock(&qtldr_lock);
    qtldr_crash_dump_internal(fd, NULL);
    qemu_mutex_unlock(&qtldr_lock);

    qemu_fdatasync(fd);
    close(fd);
}
