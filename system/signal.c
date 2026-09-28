/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "system/signal.h"
#include "hw/core/cpu.h"
#include "system/kvm.h"
#include "qemu/error-report.h"

#ifdef CONFIG_LINUX

#include <sys/prctl.h>

#ifndef PR_MCE_KILL
#define PR_MCE_KILL 33
#endif

#ifndef PR_MCE_KILL_SET
#define PR_MCE_KILL_SET 1
#endif

#ifndef PR_MCE_KILL_EARLY
#define PR_MCE_KILL_EARLY 1
#endif

#endif /* CONFIG_LINUX */


#ifdef CONFIG_LINUX
static void sigbus_reraise(void)
{
    sigset_t set;
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (!sigaction(SIGBUS, &action, NULL)) {
        raise(SIGBUS);
        sigemptyset(&set);
        sigaddset(&set, SIGBUS);
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    }
    perror("Failed to re-raise SIGBUS!");
    abort();
}

static void sigbus_handler(int n, siginfo_t *siginfo, void *ctx)
{
    if (siginfo->si_code != BUS_MCEERR_AO &&
        siginfo->si_code != BUS_MCEERR_AR) {
        sigbus_reraise();
    }

    if (current_cpu) {
        /* Called asynchronously in VCPU thread.  */
        if (kvm_on_sigbus_vcpu(current_cpu, siginfo->si_code,
                               siginfo->si_addr)) {
            sigbus_reraise();
        }
    } else {
        /* Called synchronously (via signalfd) in main thread.  */
        if (kvm_on_sigbus(siginfo->si_code, siginfo->si_addr)) {
            sigbus_reraise();
        }
    }
}

void qemu_init_crash_signals(void)
{
    struct sigaction action;

#ifdef CONFIG_SIGALTSTACK
    static stack_t signal_stack;
    signal_stack.ss_sp = (void *)g_new0(char, SIGSTKSZ);
    signal_stack.ss_size = SIGSTKSZ;
    if (sigaltstack(&signal_stack, NULL) < 0) {
        error_printf("unable to enable alternate signal stack: %s",
                     strerror(errno));
        abort();
    }
#endif

    /*
     * ALERT: when modifying this, take care that SIGBUS forwarding in
     * qemu_prealloc_mem() will continue working as expected.
     */
    memset(&action, 0, sizeof(action));
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    action.sa_sigaction = sigbus_handler;
    sigaction(SIGBUS, &action, NULL);

    prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0);
}
#else /* !CONFIG_LINUX */
void qemu_init_crash_signals(void)
{
}
#endif /* !CONFIG_LINUX */
