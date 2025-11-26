subdir('schemavalidator')

test_sources = files('base64_test.c', 'hex_test.c', 'test-utils.c')

test_include_dirs = ['.', '../include']

cper_tests = executable(
    'cper-tests',
    'ir-tests.c',
    test_sources,
    implicit_include_directories: false,
    include_directories: include_directories(test_include_dirs),
    dependencies: [
        json_c_dep,
        jsonc_validator_dep,
        libcper_parse_dep,
        libcper_generate_dep,
    ],
)
test('test-cper-tests', cper_tests)

cc = meson.get_compiler('c')

# Fuzzing only works on linux at this moment.  osx clang doesn't have leak detector
is_darwin = host_machine.system().startswith('darwin')
if (cc.get_id() == 'clang') and get_option('fuzz').allowed() and not is_darwin
    sanitize = ['fuzzer']
    fuzz_args = [
        '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
        '-fsanitize=fuzzer,address,leak',
    ]

    foreach fuzzer_test : ['fuzz_cper_buf_to_ir']
        fuzz_exe = executable(
            fuzzer_test,
            [fuzzer_test + '.c'] + libcper_parse_sources + edk_sources + 'test-utils.c' + libcper_generate_sources,
            implicit_include_directories: false,
            include_directories: include_directories(test_include_dirs),
            c_args: fuzz_args,
            link_args: fuzz_args,
            dependencies: [json_c_dep, jsonc_validator_dep],
        )
        test(
            fuzzer_test,
            fuzz_exe,
            args: [
                '-max_total_time=10',
                '-max_len=131072',
                '-error_exitcode=1',
                '-timeout_exitcode=2',
            ],
        )
    endforeach
endif
