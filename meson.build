project(
    'libcper',
    'c',
    version: '0.1',
    meson_version: '>=1.2.0',
    default_options: [
        'c_std=c18',
        'tests=' + (meson.is_subproject() ? 'disabled' : 'enabled'),
        'warning_level=2',
        'werror=true',
    ],
)

spec_dir = meson.current_source_dir() + '/specification/json'
example_dir = meson.current_source_dir() + '/examples'
add_project_arguments(
    [
        '-DLIBCPER_EXAMPLES="' + example_dir + '"',
        '-DLIBCPER_JSON_SPEC="' + spec_dir + '"',
        '-D_POSIX_C_SOURCE=200809L',
    ],
    language: 'c',
)

library_is_share = get_option('default_library') == 'shared'

if get_option('output-all-properties').enabled()
    add_project_arguments('-DOUTPUT_ALL_PROPERTIES', language: 'c')
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

json_c = dependency('json-c', default_options: {'warning_level': '0'})
json_c_dep = declare_dependency(
    include_directories: include_directories('subprojects'),
    dependencies: json_c,
)
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

install = get_option('install').allowed()

libcper_parse = library(
    'cper-parse',
    libcper_parse_sources,
    edk_sources,
    version: meson.project_version(),
    include_directories: libcper_include_dir,
    c_args: '-Wno-address-of-packed-member',
    dependencies: [json_c_dep],
    install: install,
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
    install: install,
)
libcper_generate_dep = declare_dependency(
    include_directories: libcper_include_dir,
    link_with: libcper_generate,
)

if get_option('pkgconfig').allowed()
    import('pkgconfig').generate(
        libcper_parse,
        name: meson.project_name(),
        version: meson.project_version(),
        description: 'C bindings for parsing CPER',
    )
endif

if get_option('utility').allowed()
    executable(
        'cper-convert',
        'cli-app/cper-convert.c',
        include_directories: libcper_include_dir,
        dependencies: [json_c_dep],
        link_with: [libcper_parse, libcper_generate],
        install: install,
        install_dir: get_option('bindir'),
    )

    executable(
        'cper-generate',
        'generator/cper-generate-cli.c',
        edk_sources,
        include_directories: libcper_include_dir,
        link_with: [libcper_parse, libcper_generate],
        install: install,
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

if get_option('python').allowed()
    py = import('python').find_installation(pure: false)
    py.extension_module(
        'cper',
        'pycper.c',
        c_args: ['-DLIBCPER_PYTHON'],
        dependencies: [libcper_parse_dep, json_c_dep],
        install: true,
    )
endif
