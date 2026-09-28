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
    bool siginfo;
    const char *data;
} QTLDRTestData;

#define TEST_SIGINFO_NULL \
    QTLDR_DUMP_TRIGGER_PREFIX "manual\n"

#define TEST_SIGINFO_SEGV \
    QTLDR_DUMP_TRIGGER_PREFIX "\n" \
    "  - Signal: SIGSEGV (11)\n" \
    "  - Code: Address not mapped (1)\n" \
    "  - Address: 0x87539319\n"


static void
test_tldr_one(QTLDRTestData *data)
{
    g_autofree char *tmpname = NULL;
    int tmpfd;
    char buf[1024];
    ssize_t dumplen;

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


int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/util/tldr/minimal/default",
                    test_tldr_minimal_default);
    g_test_add_func("/util/tldr/minimal/siginfo",
                    test_tldr_minimal_siginfo);

    return g_test_run();
}
