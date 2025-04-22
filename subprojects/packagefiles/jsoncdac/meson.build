project(
    'libjsoncdac',
    ['c'],
    meson_version: '>=1.1.1',
    default_options: ['default_library=static', 'c_std=gnu18'],
)
conf_data = configuration_data(
    {
        'PROJECT_NAME': 'jsoncdac',
        'PROJECT_VERSION': '0.1',
        'PROJECT_VERSION_MAJOR': '0',
        'PROJECT_VERSION_MINOR': '1',
        'PROJECT_VERSION_PATCH': '0',
    },
)
configure_file(
    input: 'config.h.in',
    output: 'version_config.h',
    configuration: conf_data,
)
deps = []

add_project_arguments('-Wno-unused-parameter', language: 'c')
add_project_arguments('-Wformat=0', language: 'c')

jsonc = dependency('json-c', static: true)
deps += jsonc

jsoncdac_sources = files(
    'libjsoncdac/additionalproperties.c',
    'libjsoncdac/contains.c',
    'libjsoncdac/dependent.c',
    #'libjsoncdac/download.c',
    #'libjsoncdac/jdac-cli.c',
    'libjsoncdac/output.c',
    'libjsoncdac/pattern.c',
    'libjsoncdac/patternproperties.c',
    'libjsoncdac/propertynames.c',
    'libjsoncdac/ref.c',
    'libjsoncdac/regex_match.c',
    'libjsoncdac/store.c',
    'libjsoncdac/subschemalogic.c',
    'libjsoncdac/validate.c',
)

jsoncdac_deps = [dependency('json-c')]
cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required: false)
if m_dep.found()
    deps += m_dep
endif

jsoncdac = library(
    'jsoncdac',
    jsoncdac_sources,
    dependencies: deps,
    include_directories: include_directories('..'),
)

jsoncdac_dep = declare_dependency(
    link_with: jsoncdac,
    dependencies: deps,
    include_directories: include_directories('include', '..'),
)
