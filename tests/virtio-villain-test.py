#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ANSI = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|'
    r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b[ -/]*[@-Z\\-_a-z]')

ACCEL_ENV = 'QEMU_TEST_VIRTIO_VILLAIN_ACCEL'
ACCELERATORS = ('kvm', 'tcg')


def clean(text):
    return ANSI.sub('', text.replace('\r\n', '\n').replace('\r', '\n'))


def selected_accel():
    accel = os.environ.get(ACCEL_ENV, 'kvm')
    if accel not in ACCELERATORS:
        choices = ', '.join(ACCELERATORS)
        raise ValueError(f'{ACCEL_ENV} must be one of {choices}')
    return accel


def outcome(report, name, returncode):
    cases = report['tests']
    if not cases and returncode == 0:
        return 77
    if len(cases) != 1 or cases[0]['name'] != name:
        raise ValueError(f'Expected exactly one result for {name}')
    status = cases[0]['status']
    if status in ('FAIL', 'WEDGED', 'XPASS'):
        return 1
    if returncode != 0:
        return 1
    if status in ('SKIP', 'XFAIL'):
        return 77
    if status in ('PASS', 'REJECT'):
        return 0
    raise ValueError(f'Unknown virtio-villain status: {status}')


def kernel_path(build, name):
    filename = 'mmio-kernel' if name.startswith('M') else 'kernel'
    return Path(build) / filename


def run_runner(source, build, arguments):
    loader = importlib.machinery.SourceFileLoader('virtio_villain', source)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    runner = importlib.util.module_from_spec(spec)
    loader.exec_module(runner)
    # Separate runner processes otherwise allocate the same host vsock CIDs.
    runner.Qemu._cid_counter = os.getpid() * 256
    sys.argv = [
        source,
        '--init', str(Path(build) / 'target/init'),
        '--initramfs', str(Path(build) / 'target/initramfs.cpio.gz'),
        '--accel', selected_accel(),
        *arguments,
    ]
    runner.main()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('name')
    args = parser.parse_args()
    try:
        selected_accel()
    except ValueError as error:
        parser.error(str(error))
    logs = args.build / 'logs'
    logs.mkdir(exist_ok=True)
    report_path = logs / f'{args.name}.json'
    log_path = logs / f'{args.name}.log'
    report_path.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)
    result = subprocess.run(
        [sys.executable, '-B', str(Path(__file__).resolve()), '--runner',
         str(args.source / 'run'), str(args.build),
         '-m', args.qemu, '-k',
         str(kernel_path(args.build, args.name)),
         '--transport', 'mmio' if args.name.startswith('M') else 'pci',
         '--skip-unsupported', '-j', '1',
         '--log-dir', str(logs),
         '--format', 'json', '--output', str(report_path),
         args.name], capture_output=True, text=True, errors='replace',
        check=False)
    text = clean(result.stdout) + clean(result.stderr)
    serial = clean(log_path.read_text(errors='replace')) \
        if log_path.exists() else None
    code = 1
    try:
        if not report_path.exists():
            raise ValueError('virtio-villain produced no JSON report')
        with report_path.open() as stream:
            report = json.load(stream)
        for case in report['tests']:
            text += ('\n{status} {name} (spec {spec_section}) '
                     '{description}\n').format(**case)
            text += serial if serial is not None else \
                clean(case.get('output') or '')
        code = outcome(report, args.name, result.returncode)
    except (OSError, ValueError, KeyError, TypeError) as error:
        text += f'\nERROR: invalid virtio-villain result: {error}\n'
    log_path.write_text(text)
    print(text, end='')
    print(f'\nFull virtio-villain log: {log_path}')
    return code


class Helpers(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(clean('\x1bc\x1b[?7lA\r\nB\rC\x1b[0m'),
                         'A\nB\nC')
        self.assertEqual(clean('\x1b]0;title\x07text'), 'text')

    def test_outcomes(self):
        for status, expected in (
                ('PASS', 0), ('REJECT', 0), ('SKIP', 77), ('XFAIL', 77),
                ('FAIL', 1), ('WEDGED', 1), ('XPASS', 1)):
            with self.subTest(status=status):
                report = {'tests': [{'name': 'RNG0001', 'status': status}]}
                self.assertEqual(outcome(report, 'RNG0001', 0), expected)

    def test_runner_error_is_failure(self):
        report = {'tests': [{'name': 'RNG0001', 'status': 'PASS'}]}
        self.assertEqual(outcome(report, 'RNG0001', 1), 1)
        self.assertEqual(outcome({'tests': []}, 'M0001', 0), 77)
        with self.assertRaises(ValueError):
            outcome({'tests': []}, 'RNG0001', 1)

    def test_wrong_case_is_error(self):
        with self.assertRaises(ValueError):
            outcome({'tests': [{'name': 'OTHER', 'status': 'PASS'}]},
                    'RNG0001', 0)

    def test_unknown_status_is_error(self):
        with self.assertRaises(ValueError):
            outcome({'tests': [{'name': 'RNG0001', 'status': 'UNKNOWN'}]},
                    'RNG0001', 0)

    def test_runner_configuration(self):
        runner = types.SimpleNamespace(
            main=mock.Mock(),
            Qemu=types.SimpleNamespace())
        with mock.patch.object(importlib.machinery.SourceFileLoader,
                               'exec_module'), \
             mock.patch.object(importlib.util, 'module_from_spec',
                               return_value=runner), \
             mock.patch.object(sys, 'argv', []), \
             mock.patch.object(os, 'getpid', return_value=123):
            run_runner('/source/run', '/build', ['RNG0001'])
            self.assertEqual(runner.Qemu._cid_counter, 123 * 256)
            runner.main.assert_called_once_with()
            accel = sys.argv[sys.argv.index('--accel') + 1]
            self.assertIn(accel, ACCELERATORS)
            self.assertEqual(sys.argv, [
                '/source/run',
                '--init', '/build/target/init',
                '--initramfs', '/build/target/initramfs.cpio.gz',
                '--accel', accel,
                'RNG0001',
            ])

    def test_runner_can_select_tcg(self):
        runner = types.SimpleNamespace(
            main=mock.Mock(),
            Qemu=types.SimpleNamespace())
        with mock.patch.object(importlib.machinery.SourceFileLoader,
                               'exec_module'), \
             mock.patch.object(importlib.util, 'module_from_spec',
                               return_value=runner), \
             mock.patch.object(sys, 'argv', []), \
             mock.patch.dict(os.environ,
                             {'QEMU_TEST_VIRTIO_VILLAIN_ACCEL': 'tcg'}):
            run_runner('/source/run', '/build', ['RNG0001'])
            self.assertEqual(sys.argv[sys.argv.index('--accel') + 1], 'tcg')
            runner.main.assert_called_once_with()

    def test_kernel_selection(self):
        for name in ('RNG0001', 'B0201', 'PCI0200'):
            with self.subTest(name=name):
                self.assertEqual(kernel_path(Path('/build'), name),
                                 Path('/build/kernel'))
        self.assertEqual(kernel_path(Path('/build'), 'M0010'),
                         Path('/build/mmio-kernel'))

    def test_build_uses_only_cloud_hypervisor_kernels(self):
        script = Path(__file__).with_name('virtio-villain-build.py')
        builder = runpy.run_path(str(script))
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(arch=arch), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kernel = root / 'download'
                kernel.write_bytes(b'kernel')
                asset_type = mock.Mock()
                asset_type.return_value.fetch.return_value = kernel
                argv = [
                    'build', '--source', '/source', '--build', directory,
                    '--arch', arch, '--stamp', str(root / 'stamp'),
                    '--make', 'make', '--', 'cc',
                ]
                with mock.patch.object(sys, 'argv', argv), \
                     mock.patch.object(subprocess, 'run') as build, \
                     mock.patch.object(runpy, 'run_path',
                                       return_value={'Asset': asset_type}):
                    builder['main']()
                expected = [
                    mock.call(builder['KERNEL_URL'] + filename, digest)
                    for filename, digest in [builder['KERNELS'][arch]]
                    + ([builder['MMIO_KERNEL']] if arch == 'x86_64' else [])
                ]
                self.assertEqual(asset_type.call_args_list, expected)
                self.assertEqual(asset_type.return_value.fetch.call_count,
                                 len(expected))
                build.assert_called_once_with(
                    ['make', '-C', '/source', 'initramfs',
                     f'TARGET={root / "target"}', 'CC=cc'], check=True)
                self.assertEqual((root / 'kernel').read_bytes(), b'kernel')
                self.assertEqual((root / 'mmio-kernel').read_bytes(),
                                 b'kernel')
                self.assertFalse((root / 'hotplug-kernel').exists())
                self.assertTrue((root / 'stamp').exists())

    def test_full_readable_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = {'name': 'RNG0001', 'status': 'PASS',
                    'spec_section': '5.4.6',
                    'description': 'RNG basic request',
                    'output': ''}

            def run(*unused_args, **unused_kwargs):
                (root / 'logs/RNG0001.json').write_text(
                    json.dumps({'tests': [case]}))
                (root / 'logs/RNG0001.log').write_bytes(
                    b'\x1bcguest\r\n[PASS] RNG0001\r\n')
                return subprocess.CompletedProcess([], 0, '[PASS]\n', '')

            argv = ['test', '--build', directory, '--source', '/source',
                    '--qemu', '/build/qemu-system-x86_64', 'RNG0001']
            with mock.patch.object(sys, 'argv', argv), \
                 mock.patch.object(subprocess, 'run', side_effect=run), \
                 mock.patch('builtins.print') as output:
                self.assertEqual(main(), 0)
            text = (root / 'logs/RNG0001.log').read_bytes()
            self.assertIn(b'guest\n[PASS] RNG0001\n', text)
            self.assertNotIn(b'\r', text)
            self.assertNotIn(b'\x1b', text)
            self.assertIn(str(root / 'logs/RNG0001.log'),
                          output.call_args.args[0])

    def test_explicit_transport(self):
        for name, transport in (('RNG0001', 'pci'), ('M0010', 'mmio')):
            with self.subTest(name=name), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                case = {'name': name, 'status': 'PASS',
                        'spec_section': '4', 'description': 'Test case'}

                def run(command, **kwargs):
                    index = command.index('--transport')
                    self.assertEqual(command[index + 1], transport)
                    (root / f'logs/{name}.json').write_text(
                        json.dumps({'tests': [case]}))
                    return subprocess.CompletedProcess(command, 0, '', '')

                argv = ['test', '--build', directory, '--source', '/source',
                        '--qemu', '/build/qemu-system-x86_64', name]
                with mock.patch.object(sys, 'argv', argv), \
                     mock.patch.object(subprocess, 'run', side_effect=run), \
                     mock.patch('builtins.print'):
                    self.assertEqual(main(), 0)

    def test_source_discovery(self):
        script = Path(__file__).with_name('virtio-villain-list.py')
        discover = runpy.run_path(str(script))['test_names']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tests/rng').mkdir(parents=True)
            (root / 'tests/rng/rng0001_basic.c').touch()
            (root / 'tests/rng/rng_helpers.c').touch()
            self.assertEqual(discover(root), ['RNG0001-basic'])
            (root / 'tests/rng/rng0002_invalid_length.c').touch()
            self.assertEqual(discover(root),
                             ['RNG0001-basic', 'RNG0002-invalid-length'])
            (root / 'tests/rng/rng0001_duplicate.c').touch()
            with self.assertRaises(ValueError):
                discover(root)

    def test_initialization_keeps_stdout_machine_readable(self):
        script = Path(__file__).with_name('virtio-villain-list.py')
        list_main = runpy.run_path(str(script))['main']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()

            def initialize(*unused_args, **kwargs):
                print('Submodule initialized', file=kwargs['stdout'])
                source = root / 'tests/virtio-villain'
                (source / 'tests/rng').mkdir(parents=True)
                (source / 'Makefile').touch()
                (source / 'tests/rng/rng0001_basic.c').touch()

            output, diagnostic = io.StringIO(), io.StringIO()
            with mock.patch.dict(
                    list_main.__globals__,
                    {'__file__': str(root / 'tests' / script.name)}), \
                 mock.patch.object(sys, 'argv', ['list']), \
                 mock.patch.object(
                     subprocess, 'run', side_effect=initialize), \
                 contextlib.redirect_stdout(output), \
                 contextlib.redirect_stderr(diagnostic):
                list_main()
            self.assertEqual(output.getvalue(), 'RNG0001-basic\n')
            self.assertIn('Submodule initialized', diagnostic.getvalue())


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]])
    elif sys.argv[1:2] == ['--runner']:
        run_runner(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        sys.exit(main())
