/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-i386.h"

void qmp_rtc_reset_reinjection(Error **errp)
{
    /* Nothing to do since non-x86 machines lack an RTC */
}
