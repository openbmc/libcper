cmake = import('cmake')

gtest = dependency('gtest', disabler: true, required: false)
gmock = dependency('gmock', disabler: true, required: false)
if not gtest.found() or not gmock.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ],
        )
        gmock = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').allowed(),
            'Googletest is required if tests are enabled',
        )
    endif
endif

nlohmann_json_dep = dependency(
    'nlohmann_json',
    required: false,
    version: '>=3.11.2',
    include_type: 'system',
)
if not nlohmann_json_dep.found()
    nlohmann_proj = subproject('nlohmann_json', required: true)
    nlohmann_json_dep = nlohmann_proj.get_variable('nlohmann_json_dep')
endif

valijson_dep = dependency('valijson', required: false)
if not valijson_dep.found()
    valijson_proj = cmake.subproject('valijson')
    valijson_dep = valijson_proj.get_variable('valijson_dep')
endif

test_sources = ['test-utils.cpp', 'base64_test.cpp']

test_include_dirs = ['.', '../include']

cper_tests = executable(
    'cper-tests',
    'ir-tests.cpp',
    test_sources,
    implicit_include_directories: false,
    include_directories: include_directories(test_include_dirs),
    cpp_args: '-fpermissive',
    dependencies: [
        libcper_parse_dep,
        libcper_generate_dep,
        json_c_dep,
        gtest,
        gmock,
        nlohmann_json_dep,
        valijson_dep,
    ],
)
test('test-cper-tests', cper_tests)

cxx = meson.get_compiler('cpp')

# Fuzzing only works on linux at this moment.  osx clang doesn't have leak detector
is_darwin = host_machine.system().startswith('darwin')
if (cxx.get_id() == 'clang') and get_option('fuzz').allowed() and not is_darwin
    sanitize = ['fuzzer']
    fuzz_args = [
        '-fsanitize=' + ','.join(sanitize),
        '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
    ]

    foreach fuzzer_test : ['fuzz_cper_buf_to_ir']
        fuzz_exe = executable(
            fuzzer_test,
            [fuzzer_test + '.cpp'] + libcper_parse_sources + edk_sources + test_sources + libcper_generate_sources,
            implicit_include_directories: false,
            include_directories: include_directories(test_include_dirs),
            cpp_args: fuzz_args,
            c_args: fuzz_args,
            link_args: fuzz_args,
            dependencies: [
                json_c_dep,
                gtest,
                gmock,
                nlohmann_json_dep,
                valijson_dep,
            ],
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
