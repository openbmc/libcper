project(
    'libcper',
    ['c', 'cpp'],
    version: '0.1',
    meson_version: '>=1.1.1',
    default_options: [
        'c_std=c18',
        'cpp_std=c++23',
        'tests=' + (meson.is_subproject() ? 'disabled' : 'enabled'),
        'werror=true',
        'warning_level=2',
    ],
)

project_description = 'libcper library'

SectionSources = files(
    'sections/cper-section-arm.c',
    'sections/cper-section-ccix-per.c',
    'sections/cper-section-cxl-component.c',
    'sections/cper-section-cxl-protocol.c',
    'sections/cper-section-dmar-generic.c',
    'sections/cper-section-dmar-iommu.c',
    'sections/cper-section-dmar-vtd.c',
    'sections/cper-section-firmware.c',
    'sections/cper-section-generic.c',
    'sections/cper-section-ia32x64.c',
    'sections/cper-section-ipf.c',
    'sections/cper-section-memory.c',
    'sections/cper-section-pci-bus.c',
    'sections/cper-section-pci-dev.c',
    'sections/cper-section-pcie.c',
    'sections/cper-section.c',
)

EDKSources = files('edk/Cper.c')

GeneratorSectionSources = files(
    'generator/sections/gen-section-arm.c',
    'generator/sections/gen-section-ccix-per.c',
    'generator/sections/gen-section-cxl-component.c',
    'generator/sections/gen-section-cxl-protocol.c',
    'generator/sections/gen-section-dmar.c',
    'generator/sections/gen-section-firmware.c',
    'generator/sections/gen-section-generic.c',
    'generator/sections/gen-section-ia32x64.c',
    'generator/sections/gen-section-memory.c',
    'generator/sections/gen-section-pci-bus.c',
    'generator/sections/gen-section-pci-dev.c',
    'generator/sections/gen-section-pcie.c',
    'generator/sections/gen-section.c',
)

cmake = import('cmake')
cc = meson.get_compiler('c')

json_c_dep = dependency('json-c', required: true, fallback: ['json-c', 'json_c_dep'])

libb64 = cc.find_library('base64', has_headers: 'libbase64.h', required: false)
if not libb64.found()
    opt_var = cmake.subproject_options()
    opt_var.add_cmake_defines(
        {
            'BUILD_SHARED_LIBS': true,
            'BASE64_BUILD_CLI': false,
            'BASE64_WITH_AVX': false,
            'BASE64_WITH_AVX2': false,
            'BASE64_WITH_AVX512': false,
            'BASE64_WITH_SSSE3': false,
            'BASE64_WITH_SSE41': false,
            'BASE64_WITH_SSE42': false,
        },
    )


    libb64_ex = cmake.subproject('libb64', options: opt_var)
    libb64 = libb64_ex.dependency('base64')
endif

libcper_parse_sources = [
    'cper-parse.c',
    'ir-parse.c',
    'cper-utils.c',
    'common-utils.c',
    'json-schema.c',
]

libcper_include = ['.']

libcper_parse = library(
    'cper-parse',
    libcper_parse_sources,
    SectionSources,
    EDKSources,
    version: meson.project_version(),
    include_directories: include_directories(libcper_include),
    c_args: '-Wno-address-of-packed-member',
    dependencies: [
        json_c_dep,
        libb64,
    ],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_parse = declare_dependency(
    include_directories: include_directories(libcper_include),
    link_with: libcper_parse,
)

libcper_generate_sources = ['generator/cper-generate.c', 'generator/gen-utils.c', 'common-utils.c']

libcper_generate = library(
    'cper-generate',
    libcper_generate_sources,
    GeneratorSectionSources,
    version: meson.project_version(),
    include_directories: include_directories(libcper_include),
    dependencies: [
        libcper_parse,
        json_c_dep,
        libb64,
    ],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_generate = declare_dependency(
    include_directories: include_directories(libcper_include),
    link_with: libcper_generate,
)

install_headers('cper-parse.h')
install_headers('cper-utils.h')
install_headers('common-utils.h')
install_headers('generator/cper-generate.h', subdir: 'generator')
install_headers('edk/Cper.h', subdir: 'edk')
install_headers('edk/BaseTypes.h', subdir: 'edk')

if get_option('utility').allowed()
    executable(
        'cper-convert',
        'cli-app/cper-convert.c',
        include_directories: include_directories(libcper_include),
        dependencies: [
            libcper_parse,
            json_c_dep,
        ],
        install: true,
        install_dir: get_option('bindir'),
    )

    executable(
        'cper-generate',
        'generator/cper-generate-cli.c',
        EDKSources,
        include_directories: include_directories(libcper_include),
        dependencies: [
            libcper_generate,
        ],
        install: true,
        install_dir: get_option('bindir'),
    )
endif

run_command('cp', '-r', 'specification/json/', meson.current_build_dir(), check: true)
run_command(
    'mv',
    meson.current_build_dir() / 'json',
    meson.current_build_dir() / 'specification',
)

if get_option('tests').allowed()
    subdir('tests')
endif
