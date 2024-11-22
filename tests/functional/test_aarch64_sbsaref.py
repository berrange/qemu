#!/usr/bin/env python3
#
# Functional test that boots a kernel and checks the console
#
# SPDX-FileCopyrightText: 2023-2024 Linaro Ltd.
# SPDX-FileContributor: Philippe Mathieu-Daudé <philmd@linaro.org>
# SPDX-FileContributor: Marcin Juszkiewicz <marcin.juszkiewicz@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os

from qemu_test import (QemuSystemTest, Asset, wait_for_console_pattern,
                       interrupt_interactive_console_until_pattern)
from qemu_test.utils import lzma_uncompress

def fetch_firmware(test):
    """
    Flash volumes generated using:

    Toolchain from Debian:
    aarch64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0

    Used components:

    - Trusted Firmware         v2.11.0
    - Tianocore EDK2           4d4f569924
    - Tianocore EDK2-platforms 3f08401

    """

    # Secure BootRom (TF-A code)
    fs0_xz_path = Aarch64SbsarefMachine.ASSET_FLASH0.fetch()
    fs0_path = os.path.join(test.workdir, "SBSA_FLASH0.fd")
    lzma_uncompress(fs0_xz_path, fs0_path)

    # Non-secure rom (UEFI and EFI variables)
    fs1_xz_path = Aarch64SbsarefMachine.ASSET_FLASH1.fetch()
    fs1_path = os.path.join(test.workdir, "SBSA_FLASH1.fd")
    lzma_uncompress(fs1_xz_path, fs1_path)

    for path in [fs0_path, fs1_path]:
        with open(path, "ab+") as fd:
            fd.truncate(256 << 20)  # Expand volumes to 256MiB

    test.set_machine('sbsa-ref')
    test.vm.set_console()
    test.vm.add_args(
        "-drive", f"if=pflash,file={fs0_path},format=raw",
        "-drive", f"if=pflash,file={fs1_path},format=raw",
    )


class Aarch64SbsarefMachine(QemuSystemTest):
    """
    As firmware runs at a higher privilege level than the hypervisor we
    can only run these tests under TCG emulation.
    """

    timeout = 180

    ASSET_FLASH0 = Asset(
        ('https://artifacts.codelinaro.org/artifactory/linaro-419-sbsa-ref/'
         '20240619-148232/edk2/SBSA_FLASH0.fd.xz'),
        '0c954842a590988f526984de22e21ae0ab9cb351a0c99a8a58e928f0c7359cf7')

    ASSET_FLASH1 = Asset(
        ('https://artifacts.codelinaro.org/artifactory/linaro-419-sbsa-ref/'
         '20240619-148232/edk2/SBSA_FLASH1.fd.xz'),
        'c6ec39374c4d79bb9e9cdeeb6db44732d90bb4a334cec92002b3f4b9cac4b5ee')

    def test_sbsaref_edk2_firmware(self):

        fetch_firmware(self)

        self.vm.add_args('-cpu', 'cortex-a57')
        self.vm.launch()

        # TF-A boot sequence:
        #
        # https://github.com/ARM-software/arm-trusted-firmware/blob/v2.8.0/\
        #     docs/design/trusted-board-boot.rst#trusted-board-boot-sequence
        # https://trustedfirmware-a.readthedocs.io/en/v2.8/\
        #     design/firmware-design.html#cold-boot

        # AP Trusted ROM
        wait_for_console_pattern(self, "Booting Trusted Firmware")
        wait_for_console_pattern(self, "BL1: v2.11.0(release):")
        wait_for_console_pattern(self, "BL1: Booting BL2")

        # Trusted Boot Firmware
        wait_for_console_pattern(self, "BL2: v2.11.0(release)")
        wait_for_console_pattern(self, "Booting BL31")

        # EL3 Runtime Software
        wait_for_console_pattern(self, "BL31: v2.11.0(release)")

        # Non-trusted Firmware
        wait_for_console_pattern(self, "UEFI firmware (version 1.0")
        interrupt_interactive_console_until_pattern(self, "QEMU SBSA-REF Machine")

if __name__ == '__main__':
    QemuSystemTest.main()
