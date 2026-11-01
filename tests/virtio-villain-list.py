#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
from pathlib import Path
import re
import subprocess
import sys


def test_names(source):
    names = []
    ids = set()
    for path in sorted((source / 'tests').glob('*/*.c')):
        parts = path.stem.split('_', 1)
        name = parts[0].upper()
        if not re.fullmatch(r'[A-Z]+[0-9]+', name):
            continue
        if name in ids:
            raise ValueError(f'Duplicate virtio-villain test ID: {name}')
        ids.add(name)
        description = parts[1].replace('_', '-') if len(parts) == 2 else ''
        names.append(f'{name}-{description}' if description else name)
    if not names:
        raise ValueError('Missing or duplicate virtio-villain test names')
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-download', action='store_true')
    parser.add_argument('--sources', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = root / 'tests/virtio-villain'
    if not (source / 'Makefile').exists():
        if args.no_download or not (root / '.git').exists():
            parser.error('Initialize tests/virtio-villain with '
                         'git submodule update --init tests/virtio-villain')
        subprocess.run(['git', 'submodule', 'update', '--init',
                        'tests/virtio-villain'], cwd=root, check=True,
                       stdout=sys.stderr)
    if args.sources:
        paths = [source / 'Makefile', source / 'run']
        paths += sorted(source.glob('**/*.c'))
        paths += sorted(source.glob('**/*.h'))
        print('\n'.join(str(path) for path in paths))
    else:
        print('\n'.join(test_names(source)))


if __name__ == '__main__':
    main()
