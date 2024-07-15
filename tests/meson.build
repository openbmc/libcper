gtest = dependency('gtest', main: true, disabler: true, required: false)
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

sources = [
    'ir-tests.cpp',
    'test-utils.cpp',
    'base64_test.cpp',
]

test_include_dirs = ['.', '..']

run_command('cp', '-r', '../specification/json/', meson.current_build_dir())
run_command(
    'mv',
    meson.current_build_dir() / 'json',
    meson.current_build_dir() / 'specification',
)

tests = ['cper-tests']

test(
    'test-cper-tests',
    executable(
        'cper-tests',
        sources,
        implicit_include_directories: false,
        include_directories: include_directories(test_include_dirs),
        cpp_args: '-fpermissive',
        dependencies: [libcper_parse, libcper_generate, json_c_dep, gtest, gmock],
    ),
)
