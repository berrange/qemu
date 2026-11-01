subdir('bench')
subdir('qemu-iotests')

if host_os == 'linux' and not meson.is_cross_build() and \
   cpu in ['x86_64', 'aarch64'] and \
   emulators.has_key('qemu-system-' + cpu)

  villain_make = find_program('make', required: false)
  villain_strip = find_program('strip', required: false)
  villain_cpio = find_program('cpio', required: false)
  villain_gzip = find_program('gzip', required: false)

  if villain_make.found() and villain_strip.found() and \
     villain_cpio.found() and villain_gzip.found()
    villain_list = files('virtio-villain-list.py')
    villain_list_args = get_option('wrap_mode') == 'nodownload' ? \
                        ['--no-download'] : []

    villain_names = run_command(
      python, villain_list, villain_list_args, check: true
    ).stdout().strip().split()
    villain_sources = run_command(
      python, villain_list, villain_list_args, '--sources', check: true
    ).stdout().strip().split('\n')

    villain_cc = meson.get_compiler('c', native: true).cmd_array()
    villain_build_dir = meson.current_build_dir() / 'virtio-villain-build'

    villain_initramfs = custom_target(
      'virtio-villain-initramfs',
      output: 'virtio-villain-initramfs.stamp',
      command: [python, files('virtio-villain-build.py'),
                '--source', meson.current_source_dir() / 'virtio-villain',
                '--build', villain_build_dir, '--arch', cpu,
                '--stamp', '@OUTPUT@', '--make', villain_make.full_path(),
                '--'] + villain_cc,
      depend_files: files(villain_sources
                          + ['functional/qemu_test/asset.py']),
      build_by_default: false)

    foreach name : villain_names
      test(name, python,
           args: [files('virtio-villain-test.py'),
                  '--build', villain_build_dir,
                  '--source', meson.current_source_dir() / 'virtio-villain',
                  '--qemu', emulators['qemu-system-' + cpu].full_path(),
                  name.split('-')[0]],
           depends: [villain_initramfs, emulators['qemu-system-' + cpu]],
           suite: ['virtio-villain-optional'], timeout: 90)
    endforeach

  else
    message('virtio-villain requires make, strip, cpio and gzip')
  endif
endif


test_qapi_outputs = [
  'qapi-builtin-types.c',
  'qapi-builtin-types.h',
  'qapi-builtin-visit.c',
  'qapi-builtin-visit.h',
  'test-qapi-commands-sub-sub-module.c',
  'test-qapi-commands-sub-sub-module.h',
  'test-qapi-commands.c',
  'test-qapi-commands.h',
  'test-qapi-emit-events.c',
  'test-qapi-emit-events.h',
  'test-qapi-events-sub-sub-module.c',
  'test-qapi-events-sub-sub-module.h',
  'test-qapi-events.c',
  'test-qapi-events.h',
  'test-qapi-features.c',
  'test-qapi-features.h',
  'test-qapi-init-commands.c',
  'test-qapi-init-commands.h',
  'test-qapi-introspect.c',
  'test-qapi-introspect.h',
  'test-qapi-types-sub-sub-module.c',
  'test-qapi-types-sub-sub-module.h',
  'test-qapi-types.c',
  'test-qapi-types.h',
  'test-qapi-visit-sub-sub-module.c',
  'test-qapi-visit-sub-sub-module.h',
  'test-qapi-visit.c',
  'test-qapi-visit.h',
]

# Problem: to generate trace events, we'd have to add the .trace-events
# file to qapi_trace_events like we do in qapi/meson.build.  Since
# qapi_trace_events is used by trace/meson.build, we'd have to move
# subdir('tests') above subdir('trace') in the top-level meson.build.
# Can't, because it would break the dependency of qga on qemuutil (which
# depends on trace_ss).  Not worth solving now; simply suppress trace
# event generation instead.
test_qapi_files = custom_target('Test QAPI files',
                                output: test_qapi_outputs,
                                input: files('qapi-schema/qapi-schema-test.json',
                                             'qapi-schema/include/sub-module.json',
                                             'qapi-schema/sub-sub-module.json'),
                                command: [ qapi_gen, '-o', meson.current_build_dir(),
                                           '-b', '-p', 'test-', '@INPUT0@',
                                           '--suppress-tracing' ],
                                depend_files: qapi_gen_depends)

# meson doesn't like generated output in other directories
# perhaps change qapi_gen to replace / with _, like Meson itself does?
subdir('include')

test_qapi_sources = []
test_qapi_headers = []
i = 0
foreach o: test_qapi_files.to_list() + test_qapi_files_extra.to_list()
  if o.full_path().endswith('.h')
    test_qapi_headers += o
  endif
  test_qapi_sources += o
endforeach

libtestqapi = static_library('testqapi', sources: [genh, test_qapi_sources])
testqapi = declare_dependency(link_with: libtestqapi, sources: [genh, test_qapi_headers])

test_deps = {
  'test-qht-par': qht_bench,
}

subdir('decode')

if 'CONFIG_TCG' in config_all_accel
  subdir('fp')
  subdir('tcg')
endif

subdir('audio')
subdir('unit')
subdir('qapi-schema')
subdir('qtest')
subdir('migration-stress')
subdir('functional')
subdir('tracetool')
