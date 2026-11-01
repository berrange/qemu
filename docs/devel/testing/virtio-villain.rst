.. SPDX-License-Identifier: GPL-2.0-or-later

virtio-villain
==============

The virtio-villain suite tests how QEMU handles invalid virtio driver
input. The harness boots a separate guest for each case to isolate
crashes. Meson registers each case individually and controls parallel
execution, timeouts and results.

Requirements
------------

The suite supports native Linux x86_64 and aarch64 builds with the
matching system emulator enabled. It uses KVM by default. Set
``QEMU_TEST_VIRTIO_VILLAIN_ACCEL=tcg`` to run with TCG. Cross builds are
not supported.
Building the static guest init requires make, strip, cpio, gzip and
static C library support in the C compiler configured by Meson.

Meson initializes the submodule at ``tests/virtio-villain`` during
configuration.
With automatic downloads disabled, initialize the submodule manually
before configuring QEMU::

  git submodule update --init tests/virtio-villain

Running the suite
-----------------

From the QEMU checkout, run::

  make check-virtio-villain

Set the accelerator explicitly when running without KVM::

  QEMU_TEST_VIRTIO_VILLAIN_ACCEL=tcg make check-virtio-villain

The target builds the guest initramfs and fetches kernels on demand.
Neither operation runs during a normal QEMU build. Generated files
stay under the build directory. Kernel downloads
reuse the QEMU asset cache and verify the SHA256 checksum. Set
``QEMU_TEST_CACHE_DIR`` to override the cache location or
``QEMU_TEST_NO_DOWNLOAD=1`` to require cached kernels.

This standalone suite is not part of the functional tests or the
default ``make check`` selection. Its Meson suite name is
``virtio-villain-optional``, following the QEMU optional suite convention.
To run one case directly through Meson::

  $BUILD-DIR/run meson test RNG0001-basic

Filtering cases
---------------

Meson test names combine the case ID with a description from the source
filename, for example ``RNG0001-basic``. The suite identifies them as
virtio-villain tests without repeating that prefix in every name.

Pass Meson name filters through ``MTESTARGS`` to run one case by ID::

  make check-virtio-villain MTESTARGS='RNG0001-*'

Use a wildcard to run a group of cases::

  make check-virtio-villain MTESTARGS='RNG*'

Multiple filters select the union of their matches::

  make check-virtio-villain \
    MTESTARGS='RNG* B0196-*'

List matching cases without running them::

  $BUILD-DIR/run meson test --suite virtio-villain-optional --list 'RNG*'

Quote wildcard filters to prevent shell expansion. These are Meson
test name filters, not the directory filters of the villain runner.

Results and logs
----------------

Each invocation runs one case with the QEMU binary from the build.

PASS and REJECT pass. SKIP and XFAIL are reported as skipped.
FAIL, WEDGED and XPASS fail. Runner errors and missing reports fail
rather than appearing as successful tests. Unsupported devices and
unavailable host services are skipped by the harness.

Meson reports each case separately and writes its standard text and
JUnit reports under ``<build>/meson-logs/``. Full readable case logs
and JSON reports are retained under
``<build>/tests/virtio-villain-build/logs/<case>.log`` and ``<case>.json``.
The test output always points to its case log.

The reporting helper has embedded unit tests that run without a VM::

  python3 tests/virtio-villain-test.py --self-test
