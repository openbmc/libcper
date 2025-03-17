project(
    'libcper',
    ['c', 'cpp'],
    version: '0.1',
    meson_version: '>=1.1.1',
    default_options: [
        'c_std=c18',
        'cpp_std=c++23',
        'tests=' + (meson.is_subproject() ? 'disabled' : 'enabled'),
        'warning_level=0',
        'werror=true',
        'default_library=static',
    ],
)

add_project_arguments(
    '-DLIBCPER_JSON_SPEC="'
    + meson.current_source_dir() + '/specification/json"',
    language: ['c', 'cpp'],
)

add_project_arguments('-DLIBCPER_EXAMPLES="'
    + meson.current_source_dir() + '/examples"', language: ['c', 'cpp'])

add_project_arguments('-Wno-unused-function', language: ['c', 'cpp'])

library_is_share = get_option('default_library') == 'shared'
add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')

if get_option('output-all-properties').enabled()
    add_project_arguments('-DOUTPUT_ALL_PROPERTIES', language: ['c', 'cpp'])
endif

project_description = 'libcper library'

libcper_parse_sources = files(
    'sections/cper-section-ampere.c',
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

edk_sources = files('Cper.c')

libcper_generate_sources = files(
    'generator/sections/gen-section-ampere.c',
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

json_c_dep = dependency('json-c')
libcper_include = ['include']
libcper_include_dir = include_directories(libcper_include, is_system: true)

libcper_parse_sources += files(
    'base64.c',
    'common-utils.c',
    'cper-parse.c',
    'cper-utils.c',
    'ir-parse.c',
    'log.c',
)

subdir('include')

libcper_parse = library(
    'cper-parse',
    libcper_parse_sources,
    edk_sources,
    version: meson.project_version(),
    include_directories: libcper_include_dir,
    c_args: '-Wno-address-of-packed-member',
    dependencies: [json_c_dep],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_parse_dep = declare_dependency(
    include_directories: libcper_include_dir,
    link_with: [libcper_parse],
)

libcper_generate_sources += files(
    'generator/cper-generate.c',
    'generator/gen-utils.c',
)

libcper_generate = library(
    'cper-generate',
    libcper_generate_sources,
    version: meson.project_version(),
    include_directories: libcper_include_dir,
    dependencies: [json_c_dep],
    link_with: [libcper_parse],
    install: true,
    install_dir: get_option('libdir'),
)
libcper_generate_dep = declare_dependency(
    include_directories: libcper_include_dir,
    link_with: libcper_generate,
)

import('pkgconfig').generate(
    libcper_parse,
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'C bindings for parsing CPER',
)

if get_option('utility').allowed()
    executable(
        'cper-convert',
        'cli-app/cper-convert.c',
        include_directories: libcper_include_dir,
        dependencies: [json_c_dep],
        link_with: [libcper_parse, libcper_generate],
        install: true,
        install_dir: get_option('bindir'),
    )

    executable(
        'cper-generate',
        'generator/cper-generate-cli.c',
        edk_sources,
        include_directories: libcper_include_dir,
        link_with: [libcper_parse, libcper_generate],
        install: true,
        install_dir: get_option('bindir'),
    )
endif

# Disable unit tests when output-all-properties is enabled
# because it changes CPER-IR output format.
if get_option('output-all-properties').disabled()
    if get_option('tests').allowed()
        subdir('tests')
    endif
endif
