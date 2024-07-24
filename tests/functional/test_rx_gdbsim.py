#!/usr/bin/env python3
#
# Functional test that boots a Linux kernel and checks the console
#
# Copyright (c) 2018 Red Hat, Inc.
#
# Author:
#  Cleber Rosa <crosa@redhat.com>
#
# This work is licensed under the terms of the GNU GPL, version 2 or
# later.  See the COPYING file in the top-level directory.

import os

from unittest import skipUnless
from qemu_test import QemuSystemTest, Asset
from qemu_test import exec_command_and_wait_for_pattern
from qemu_test import wait_for_console_pattern
from qemu_test.utils import gzip_uncompress


class RxGdbSimMachine(QemuSystemTest):

    timeout = 30
    KERNEL_COMMON_COMMAND_LINE = 'printk.time=0 '

    ASSET_UBOOT = Asset('https://acc.dl.osdn.jp/users/23/23888/u-boot.bin.gz',
                        '9b78dbd43b40b2526848c0b1ce9de02c24f4dcdb')
    ASSET_DTB = Asset('https://acc.dl.osdn.jp/users/23/23887/rx-virt.dtb',
                      '7b4e4e2c71905da44e86ce47adee2210b026ac18')
    ASSET_KERNEL = Asset('http://acc.dl.osdn.jp/users/23/23845/zImage',
                         '39a81067f8d72faad90866ddfefa19165d68fc99')

    @skipUnless(os.getenv('QEMU_TEST_FLAKY_TESTS'),
                'Test is unstable on GitLab')
    def test_uboot(self):
        """
        U-Boot and checks that the console is operational.
        """
        self.set_machine('gdbsim-r5f562n8')

        uboot_path_gz = self.ASSET_UBOOT.fetch()
        uboot_path = os.path.join(self.workdir, 'u-boot.bin')
        gzip_uncompress(uboot_path_gz, uboot_path)

        self.vm.set_console()
        self.vm.add_args('-bios', uboot_path,
                         '-no-reboot')
        self.vm.launch()
        uboot_version = 'U-Boot 2016.05-rc3-23705-ga1ef3c71cb-dirty'
        wait_for_console_pattern(self, uboot_version)
        gcc_version = 'rx-unknown-linux-gcc (GCC) 9.0.0 20181105 (experimental)'
        # FIXME limit baudrate on chardev, else we type too fast
        #exec_command_and_wait_for_pattern(self, 'version', gcc_version)

    @skipUnless(os.getenv('QEMU_TEST_FLAKY_TESTS'),
                'Test is unstable on GitLab')
    def test_linux_sash(self):
        """
        Boots a Linux kernel and checks that the console is operational.
        """
        self.set_machine('gdbsim-r5f562n7')

        dtb_path = self.ASSET_DTB.fetch()
        kernel_path = self.ASSET_KERNEL.fetch()

        self.vm.set_console()
        kernel_command_line = self.KERNEL_COMMON_COMMAND_LINE + 'earlycon'
        self.vm.add_args('-kernel', kernel_path,
                         '-dtb', dtb_path,
                         '-no-reboot')
        self.vm.launch()
        wait_for_console_pattern(self, 'Sash command shell (version 1.1.1)',
                                 failure_message='Kernel panic - not syncing')
        exec_command_and_wait_for_pattern(self, 'printenv', 'TERM=linux')

if __name__ == '__main__':
    QemuSystemTest.main()
