cxx_inc = include_directories('include')
cxx_src = ['src/ir.cpp']

libcper_cxx = library(
    'cper-cxx',
    cxx_src,
    version: meson.project_version(),
    include_directories: [cxx_inc, libcper_include_dir],
    dependencies: [json_c_dep, nlohmann_json_dep, libcper_parse_dep],
    install: install,
)
libcper_cxx_dep = declare_dependency(
    include_directories: cxx_inc,
    link_with: libcper_cxx,
    dependencies: [libcper_parse_dep, json_c_dep, nlohmann_json_dep],
)

install_headers(
    'include/libcper.hpp',
)

if get_option('pkgconfig').allowed()
    import('pkgconfig').generate(
        libcper_cxx,
        name: 'libcper-cxx',
        version: meson.project_version(),
        description: 'C++ (nlohmann::json) bindings for parsing CPER',
        requires: ['libcper'],
    )
endif
