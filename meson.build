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

add_project_arguments(
    '-DLIBCPER_JSON_SPEC="'
    + meson.current_source_dir()
    + '/specification/json/cper-json.json"',
    language: ['c', 'cpp'],
)

library_is_share = get_option('default_library') == 'shared'
add_project_arguments('-D_POSIX_C_SOURCE=200809L', language : 'c')

project_description = 'libcper library'

section_sources = files(
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
    'sections/cper-section-nvidia.c',
    'sections/cper-section-pci-bus.c',
    'sections/cper-section-pci-dev.c',
    'sections/cper-section-pcie.c',
    'sections/cper-section.c',
)

edk_sources = files('edk/Cper.c')

generator_section_sources = files(
    'generator/sections/gen-section-arm.c',
    'generator/sections/gen-section-ccix-per.c',
    'generator/sections/gen-section-cxl-component.c',
    'generator/sections/gen-section-cxl-protocol.c',
    'generator/sections/gen-section-dmar.c',
    'generator/sections/gen-section-firmware.c',
    'generator/sections/gen-section-generic.c',
    'generator/sections/gen-section-ia32x64.c',
    'generator/sections/gen-section-memory.c',
    'generator/sections/gen-section-nvidia.c',
    'generator/sections/gen-section-pci-bus.c',
    'generator/sections/gen-section-pci-dev.c',
    'generator/sections/gen-section-pcie.c',
    'generator/sections/gen-section.c',
)

cc = meson.get_compiler('c')

json_c_dep = dependency('json-c', required: true, fallback: ['json-c', 'json_c_dep'])

libcper_parse_sources = [
    'base64.c',
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
    section_sources,
    edk_sources,
    version: meson.project_version(),
    include_directories: include_directories(libcper_include),
    c_args: '-Wno-address-of-packed-member',
    dependencies: [
        json_c_dep,
    ],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_parse_dep = declare_dependency(
    include_directories: include_directories(libcper_include),
    link_with: libcper_parse,
)

libcper_generate_sources = ['generator/cper-generate.c', 'generator/gen-utils.c', 'common-utils.c']

libcper_generate = library(
    'cper-generate',
    libcper_generate_sources,
    generator_section_sources,
    version: meson.project_version(),
    include_directories: include_directories(libcper_include),
    dependencies: [
        libcper_parse_dep,
        json_c_dep,
    ],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_generate_dep = declare_dependency(
    include_directories: include_directories(libcper_include),
    link_with: libcper_generate,
)

import('pkgconfig').generate(
    libcper_parse,
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'C bindings for parsing CPER'
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
            libcper_parse_dep,
            json_c_dep,
        ],
        install: true,
        install_dir: get_option('bindir'),
    )

    executable(
        'cper-generate',
        'generator/cper-generate-cli.c',
        edk_sources,
        include_directories: include_directories(libcper_include),
        dependencies: [
            libcper_generate_dep,
        ],
        install: true,
        install_dir: get_option('bindir'),
    )
endif

if get_option('tests').allowed()
    subdir('tests')
endif