/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * QTest testcase for the data recorder (tldr)
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "util/tldr-internal.h"


static QTestState *qtldr_test_start(const char *crashfile)
{
    return qtest_initf("-object tldr-config,id=tldr,crash-target=%s", crashfile);
}

static void test_crash(QTestCrashType type, int signo)
{
    QTestState *qts = NULL;
    g_autofree char *crashfile = NULL;
    g_autofree char *crashreport = NULL;
    size_t crashlen = 0;
    int fd = g_file_open_tmp("tldr-test-XXXXXX",
                             &crashfile, NULL);
    assert(fd != -1);
    qts = qtldr_test_start(crashfile);

    qtest_crash(qts, type);

    assert(g_file_get_contents(crashfile, &crashreport, &crashlen, NULL));
    close(fd);
    unlink(crashfile);
    qtest_set_expected_signal(qts, signo);
    qtest_quit(qts);

    assert(crashlen != 0);
    assert(strstr(crashreport, QTLDR_DUMP_LEADER));
    assert(strstr(crashreport, QTLDR_DUMP_TRIGGER_PREFIX));
    assert(strstr(crashreport, QTLDR_DUMP_MSG_BUCKET_PREFIX));
    assert(strstr(crashreport, QTLDR_DUMP_TRAILER));
}

static void test_crash_null_pointer(void)
{
    test_crash(QTEST_CRASH_NULL_POINTER, SIGSEGV);
}

static void test_crash_invalid_addr(void)
{
    test_crash(QTEST_CRASH_INVALID_ADDR, SIGSEGV);
}

static void test_crash_mapping_not_backed(void)
{
    test_crash(QTEST_CRASH_MAPPING_NOT_BACKED, SIGBUS);
}

#if defined(__x86_64__) || defined(__aarch64__)
static void test_crash_bad_alignment(void)
{
    test_crash(QTEST_CRASH_BAD_ALIGNMENT, SIGBUS);
}
#endif

static void test_crash_fpe_div_zero(void)
{
    test_crash(QTEST_CRASH_FPE_DIV_ZERO, SIGFPE);
}

static void test_crash_assert(void)
{
    test_crash(QTEST_CRASH_ASSERT, SIGABRT);
}

static void test_crash_illegal_inst(void)
{
    test_crash(QTEST_CRASH_ILLEGAL_INST, SIGILL);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/tldr/null-pointer", test_crash_null_pointer);
    qtest_add_func("/tldr/invalid-addr", test_crash_invalid_addr);
    qtest_add_func("/tldr/mapping-not-backed", test_crash_mapping_not_backed);
#if defined(__x86_64__) || defined(__aarch64__)
    qtest_add_func("/tldr/bad-alignment", test_crash_bad_alignment);
#endif
    qtest_add_func("/tldr/fpe-div-zero", test_crash_fpe_div_zero);
    qtest_add_func("/tldr/assert", test_crash_assert);
    qtest_add_func("/tldr/illegal-inst", test_crash_illegal_inst);

    return g_test_run();
}
