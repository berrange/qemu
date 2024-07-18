# QEMU functional tests:
# Tests that are put in the 'quick' category are run by default during
# 'make check'. Everything that should not be run during 'make check'
# (e.g. tests that fetch assets from the internet) should be put into
# the 'thorough' category instead.

# Most tests run too slow with TCI enabled, so skip the functional tests there
if get_option('tcg_interpreter')
  subdir_done()
endif

# Timeouts for individual tests that can be slow e.g. with debugging enabled
test_timeouts = {
  'netdev_ethtool' : 180,
  'ppc_40p' : 240,
  'ppc64_powernv' : 120,
  'ppc64_pseries' : 120,
  's390x_ccw_virtio' : 180,
}

tests_generic = [
  'empty_cpu_model',
  'info_usernet',
  'version',
]

tests_arm_thorough = [
  'arm_canona1100',
  'arm_n8x0',
]

tests_avr_thorough = [
  'avr_mega2560',
]

tests_loongarch64_thorough = [
  'loongarch64_virt',
]

tests_microblaze_thorough = [
  'microblaze_s3adsp1800'
]

tests_microblazeel_thorough = [
  'microblazeel_s3adsp1800'
]

tests_mips64el_thorough = [
  'mips64el_loongson3v',
]

tests_ppc_quick = [
  'ppc_74xx',
]

tests_ppc_thorough = [
  'ppc_405',
  'ppc_40p',
  'ppc_bamboo',
  'ppc_mpc8544ds',
  'ppc_virtex_ml507',
]

tests_ppc64_thorough = [
  'ppc64_powernv',
  'ppc64_pseries',
]

tests_riscv32_quick = [
  'riscv_opensbi',
]

tests_riscv64_quick = [
  'riscv_opensbi',
]

tests_s390x_thorough = [
  's390x_ccw_virtio',
  's390x_topology',
]

tests_sparc64_thorough = [
  'sparc64_sun4u',
]

tests_x86_64_quick = [
  'cpu_queries',
  'mem_addr_space',
  'pc_cpu_hotplug_props',
  'virtio_version',
  'x86_cpu_model_versions',
]

tests_x86_64_thorough = [
  'netdev_ethtool',
  'virtio_gpu',
]

precache_all = []
foreach speed : ['quick', 'thorough']
  foreach dir : target_dirs
    if not dir.endswith('-softmmu')
      continue
    endif

    target_base = dir.split('-')[0]
    test_emulator = emulators['qemu-system-' + target_base]

    if speed == 'quick'
      suites = ['func-quick', 'func-' + target_base]
      target_tests = get_variable('tests_' + target_base + '_quick', []) + tests_generic
    else
      suites = ['func-' + speed, 'func-' + target_base + '-' + speed, speed]
      target_tests = get_variable('tests_' + target_base + '_' + speed, [])
    endif

    test_deps = roms
    test_env = environment()
    if have_tools
      test_env.set('QEMU_TEST_QEMU_IMG', meson.global_build_root() / 'qemu-img')
      test_deps += [qemu_img]
    endif
    test_env.set('QEMU_TEST_QEMU_BINARY',
                 meson.global_build_root() / 'qemu-system-' + target_base)
    test_env.set('QEMU_BUILD_ROOT', meson.project_build_root())
    test_env.set('PYTHONPATH', meson.project_source_root() / 'python:' +
                               meson.current_source_dir())

    foreach test : target_tests
      testname = '@0@-@1@'.format(target_base, test)
      testfile = 'test_' + test + '.py'
      testpath = meson.current_source_dir() / testfile
      teststamp = testname + '.tstamp'
      test_precache_env = environment()
      test_precache_env.set('QEMU_TEST_PRECACHE', meson.current_build_dir() / teststamp)
      test_precache_env.set('PYTHONPATH', meson.project_source_root() / 'python:' +
                                          meson.current_source_dir())
      precache = custom_target('func-precache-' + testname,
                               output: teststamp,
                               command: [python, testpath],
                               depend_files: files(testpath),
                               build_by_default: false,
                               env: test_precache_env)
      precache_all += precache

      # Ideally we would add 'precache' to 'depends' here, such that
      # 'build_by_default: false' lets the pre-caching automatically
      # run immediately before the test runs. In practice this is
      # broken in meson, with it running the pre-caching in the normal
      # compile phase https://github.com/mesonbuild/meson/issues/2518
      # If the above bug ever gets fixed, when QEMU changes the min
      # meson version, add the 'depends' and remove the custom
      # 'run_target' logic below & in Makefile.include
      test('func-' + testname,
           python,
           depends: [test_deps, test_emulator, emulator_modules],
           env: test_env,
           args: [testpath],
           protocol: 'tap',
           timeout: test_timeouts.get(test, 60),
           priority: test_timeouts.get(test, 60),
           suite: suites)
    endforeach
  endforeach
endforeach

run_target('check-func-precache',
           depends: precache_all,
           command: ['true'])
