gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
if not gtest_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ],
        )
    else
        assert(
            not get_option('tests').enabled(),
            'Googletest is required if tests and bindings-cxx are enabled',
        )
    endif
endif

cper_cxx_ir_tests = executable(
    'cper-cxx-ir-tests',
    'ir.cpp',
    include_directories: include_directories('..'),
    dependencies: [
        gtest_dep,
        libcper_cxx_dep,
        libcper_generate_dep,
    ],
)
test('test-cper-cxx-ir-tests', cper_cxx_ir_tests)

cper_cxx_examples_tests = executable(
    'cper-cxx-examples-tests',
    'examples.cpp',
    include_directories: include_directories('..'),
    dependencies: [
        gtest_dep,
        libcper_cxx_dep,
        libcper_generate_dep,
    ],
)
test('test-cper-cxx-examples-tests', cper_cxx_examples_tests)
