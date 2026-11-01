#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess


KERNELS = {
    'x86_64': (
        'vmlinux-x86_64',
        '9d3570b47d5abb069ca00edfbfcef4c68306a9c3d078a01f10082b258f1001b8'),
    'aarch64': (
        'Image-arm64',
        '69d1b1235381ec50f1b45cf771a7dff4a9013d452833ab34682d6283e2114010'),
}
KERNEL_URL = ('https://github.com/cloud-hypervisor/linux/releases/download/'
              'ch-release-v6.16.9-20260508/')
MMIO_KERNEL = (
    'bzImage-x86_64',
    '58088758f601a04ef85b09cf23db5530d51edc039ed47afbf2264c5b762cb568')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--arch', choices=KERNELS, required=True)
    parser.add_argument('--stamp', type=Path, required=True)
    parser.add_argument('--make', required=True)
    parser.add_argument('compiler', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    compiler = args.compiler
    if compiler[:1] == ['--']:
        compiler = compiler[1:]
    if not compiler:
        parser.error('a guest compiler is required')

    args.build.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [args.make, '-C', str(args.source), 'initramfs',
         f'TARGET={args.build / "target"}',
         f'CC={shlex.join(compiler)}'], check=True)
    # Load the cache helper without importing the functional test runner.
    asset_path = (Path(__file__).resolve().parent
                  / 'functional/qemu_test/asset.py')
    asset_type = runpy.run_path(str(asset_path))['Asset']
    filename, digest = KERNELS[args.arch]
    kernel = asset_type(KERNEL_URL + filename, digest).fetch()
    shutil.copyfile(kernel, args.build / 'kernel')
    if args.arch == 'x86_64':
        filename, digest = MMIO_KERNEL
        kernel = asset_type(KERNEL_URL + filename, digest).fetch()
        shutil.copyfile(kernel, args.build / 'mmio-kernel')
    else:
        shutil.copyfile(args.build / 'kernel', args.build / 'mmio-kernel')
    args.stamp.touch()


if __name__ == '__main__':
    main()
