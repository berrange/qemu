#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# LoongArch virt test.
#
# Copyright (c) 2023 Loongson Technology Corporation Limited
#

from qemu_test import QemuSystemTest, Asset
from qemu_test import exec_command_and_wait_for_pattern
from qemu_test import wait_for_console_pattern

class LoongArchMachine(QemuSystemTest):
    KERNEL_COMMON_COMMAND_LINE = 'printk.time=0 '

    timeout = 120

    ASSET_KERNEL = Asset(
        ('https://github.com/yangxiaojuan-loongson/qemu-binary/'
         'releases/download/2024-05-30/vmlinuz.efi'),
        '951b485b16e3788b6db03a3e1793c067009e31a2')
    ASSET_INITRD = Asset(
        ('https://github.com/yangxiaojuan-loongson/qemu-binary/'
         'releases/download/2024-05-30/ramdisk'),
        'c67658d9b2a447ce7db2f73ba3d373c9b2b90ab2')
    ASSET_BIOS = Asset(
        ('https://github.com/yangxiaojuan-loongson/qemu-binary/'
         'releases/download/2024-05-30/QEMU_EFI.fd'),
        'f4d0966b5117d4cd82327c050dd668741046be69')

    def wait_for_console_pattern(self, success_message, vm=None):
        wait_for_console_pattern(self, success_message,
                                 failure_message='Kernel panic - not syncing',
                                 vm=vm)

    def test_loongarch64_devices(self):

        self.set_machine('virt')

        kernel_path = self.ASSET_KERNEL.fetch()
        initrd_path = self.ASSET_INITRD.fetch()
        bios_path = self.ASSET_BIOS.fetch()

        self.vm.set_console()
        kernel_command_line = (self.KERNEL_COMMON_COMMAND_LINE +
                               'root=/dev/ram rdinit=/sbin/init console=ttyS0,115200')
        self.vm.add_args('-nographic',
                         '-smp', '4',
                         '-m', '1024',
                         '-cpu', 'la464',
                         '-kernel', kernel_path,
                         '-initrd', initrd_path,
                         '-bios', bios_path,
                         '-append', kernel_command_line)
        self.vm.launch()
        self.wait_for_console_pattern('Run /sbin/init as init process')
        exec_command_and_wait_for_pattern(self, 'cat /proc/cpuinfo',
                                          'processor		: 3')

if __name__ == '__main__':
    QemuSystemTest.main()
