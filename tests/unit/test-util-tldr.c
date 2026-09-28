/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Tests for util/tldr.c
 *
 * Copyright 2026 Red Hat, Inc.
 */

#include "qemu/osdep.h"
#include "util/tldr-internal.h"

typedef struct {
    size_t next;
    const char *msg;
} QTLDRTestStep;

typedef struct {
    bool siginfo;
    size_t capacity;
    QTLDRTestStep *steps;
    const char *data;
} QTLDRTestData;

static int timestampIndex;

#define TEST_SIGINFO_NULL \
    QTLDR_DUMP_TRIGGER_PREFIX "manual\n"

#define TEST_SIGINFO_SEGV \
    QTLDR_DUMP_TRIGGER_PREFIX "\n" \
    "  - Signal: SIGSEGV (11)\n" \
    "  - Code: Address not mapped (1)\n" \
    "  - Address: 0x87539319\n"

/*
 * Total message length including timestamp, \f, record len,
 * message and extra newline will be 58 bytes
 */
#define TEST_MSG_1_TRUNC "mnopqrstuvwxyz\n"
#define TEST_MSG_1 "abcdefghijkl" TEST_MSG_1_TRUNC
#define TEST_MSG_2 "0123456789helloworld!!@@##"
#define TEST_MSG_3 ">$><%><@@@>[*&^()]!!<<<<()\n"
#define TEST_TIMESTAMP_1_TRUNC "026-10-05T16:35:40.601961Z"
#define TEST_TIMESTAMP_1 "2" TEST_TIMESTAMP_1_TRUNC
#define TEST_TIMESTAMP_2_TRUNC "T16:38:40.601961Z"
#define TEST_TIMESTAMP_2 "2026-10-05" TEST_TIMESTAMP_2_TRUNC
#define TEST_TIMESTAMP_3 "2026-10-05T16:40:40.601961Z"


static char *
test_tldr_now_str_func(void)
{
    static const char *timestamps[] = {
        TEST_TIMESTAMP_1,
        TEST_TIMESTAMP_2,
        TEST_TIMESTAMP_3,
    };
    timestampIndex = timestampIndex % 3;
    return g_strdup(timestamps[timestampIndex++]);
}


static void
test_tldr_one(QTLDRTestData *data)
{
    QTLDRMsgBucket *bucket = &(qtldr_msg_buckets[QTLDR_MSG_BUCKET_TYPE_ERROR]);
    size_t i;
    g_autofree char *tmpname = NULL;
    int tmpfd;
    char buf[1024];
    ssize_t dumplen;

    qtldr_msg_enabled_mask = (1 << QTLDR_MSG_BUCKET_TYPE_ERROR);

    if (data->capacity && data->steps) {
        timestampIndex = 0;

        g_clear_pointer(&bucket->buf, g_free);
        bucket->allocated = 0;
        bucket->capacity = data->capacity;
        bucket->next = 0;

        for (i = 0; data->steps[i].msg; i++) {
            qtldr_msg_record(QTLDR_MSG_BUCKET_TYPE_ERROR,
                             data->steps[i].msg);

            assert(bucket->next == data->steps[i].next);
            assert(bucket->allocated == data->capacity);
            assert(bucket->capacity == data->capacity);
            assert(bucket->buf != NULL);
        }
    }

    tmpfd = g_file_open_tmp("test-util-tldr-XXXXXX",
                            &tmpname, NULL);
    unlink(tmpname);

    if (data->siginfo) {
        siginfo_t si = {};
        si.si_signo = 11; /*
                           * SIGSEGV on Linux, but don't use constant
                           * since expected output string hardcodes 11
                           */
        si.si_code = 1;
        si.si_addr = (void *)0x87539319;
        qtldr_crash_dump_internal(tmpfd, &si);
    } else {
        qtldr_crash_dump_internal(tmpfd, NULL);
    }

    lseek(tmpfd, 0, SEEK_SET);

    dumplen = read(tmpfd, buf, sizeof(buf));

    assert(dumplen > 0);
    buf[dumplen] = '\0';

    close(tmpfd);

    g_assert_cmpstr(buf, ==, data->data);
}


static void
test_tldr_minimal_default(void)
{
    QTLDRTestData data = {
        .siginfo = false,
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


static void
test_tldr_minimal_siginfo(void)
{
    QTLDRTestData data = {
        .siginfo = true,
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_SEGV
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A single message which easily fits in the buffer
 * to sanity check minimal functionality
 */
static void
test_tldr_msgs_simple(void)
{
    QTLDRTestData data = {
        .capacity = 70,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_TIMESTAMP_1 " " TEST_MSG_1
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A pair of messages which exactly hit the buffer
 * size to sanity check we wrap back to start on
 * the limit.
 */
static void
test_tldr_msgs_exact(void)
{
    QTLDRTestData data = {
        .capacity = 110,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = 0, .msg = TEST_MSG_2 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_TIMESTAMP_1 " " TEST_MSG_1
            TEST_TIMESTAMP_2 " " TEST_MSG_2 "\n"
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A pair of messages which easily exceed the buffer
 * size to sanity check we wrap and overwrite existing
 * old data
 */
static void
test_tldr_msgs_wrap_simple(void)
{
    QTLDRTestData data = {
        .capacity = 70,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = 40, .msg = TEST_MSG_2 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_MSG_1_TRUNC
            TEST_TIMESTAMP_2 " " TEST_MSG_2 "\n"
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A pair of messages which both exactly match the
 * buffer size to further sanity check wrapping
 * behaviour
 */
static void
test_tldr_msgs_wrap_exact(void)
{
    QTLDRTestData data = {
        .capacity = 55,
        .steps = (QTLDRTestStep[]){
            { .next = 0, .msg = TEST_MSG_1 },
            { .next = 0, .msg = TEST_MSG_2 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_TIMESTAMP_2 " " TEST_MSG_2 "\n"
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A set of messages where first two are one less
 * than the buffer size, to further sanity check
 * wrapping behaviour
 */
static void
test_tldr_msgs_wrap_oneextra(void)
{
    QTLDRTestData data = {
        .capacity = 111,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = 110, .msg = TEST_MSG_2 },
            { .next = 54, .msg = TEST_MSG_3 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            "\n"
            TEST_TIMESTAMP_2 " " TEST_MSG_2 "\n"
            TEST_TIMESTAMP_3 " " TEST_MSG_3
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A set of messages where first two are one larger
 * than the buffer size, to further sanity check
 * wrapping behaviour
 */
static void
test_tldr_msgs_wrap_oneunder(void)
{
    QTLDRTestData data = {
        .capacity = 109,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = 1, .msg = TEST_MSG_2 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_TIMESTAMP_1_TRUNC " " TEST_MSG_1
            TEST_TIMESTAMP_2 " " TEST_MSG_2 "\n"
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


/*
 * A set of messages that make us wrap around
 * many times over.
 */
static void
test_tldr_msgs_wrap_repeat(void)
{
    QTLDRTestData data = {
        .capacity = 100,
        .steps = (QTLDRTestStep[]){
            { .next = 55, .msg = TEST_MSG_1 },
            { .next = 10, .msg = TEST_MSG_2 },
            { .next = 65, .msg = TEST_MSG_3 },
            { .next = 20, .msg = TEST_MSG_1 },
            { .next = 75, .msg = TEST_MSG_2 },
            { .next = 30, .msg = TEST_MSG_3 },
            { .next = -1, .msg = NULL },
        },
        .data =
            QTLDR_DUMP_LEADER
            TEST_SIGINFO_NULL
            QTLDR_DUMP_MSG_BUCKET_PREFIX "error':\n"
            TEST_TIMESTAMP_2_TRUNC " " TEST_MSG_2 "\n"
            TEST_TIMESTAMP_3 " " TEST_MSG_3
            QTLDR_DUMP_TRAILER
    };

    test_tldr_one(&data);
}


int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtldr_now_str_func = test_tldr_now_str_func;

    g_test_add_func("/util/tldr/minimal/default",
                    test_tldr_minimal_default);
    g_test_add_func("/util/tldr/minimal/siginfo",
                    test_tldr_minimal_siginfo);
    g_test_add_func("/util/tldr/msgs/simple",
                    test_tldr_msgs_simple);
    g_test_add_func("/util/tldr/msgs/exact",
                    test_tldr_msgs_exact);
    g_test_add_func("/util/tldr/msgs/wrap/simple",
                    test_tldr_msgs_wrap_simple);
    g_test_add_func("/util/tldr/msgs/wrap/exact",
                    test_tldr_msgs_wrap_exact);
    g_test_add_func("/util/tldr/msgs/wrap/oneextra",
                    test_tldr_msgs_wrap_oneextra);
    g_test_add_func("/util/tldr/msgs/wrap/oneunder",
                    test_tldr_msgs_wrap_oneunder);
    g_test_add_func("/util/tldr/msgs/wrap/repeat",
                    test_tldr_msgs_wrap_repeat);

    return g_test_run();
}
