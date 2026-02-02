cc = meson.get_compiler('c')
math_dep = cc.find_library('m', required: false)

jsonc_validator = library(
    'jsonc_validator',
    ['output.c', 'validate.c'],
    dependencies: [math_dep, json_c_dep, libcper_parse_dep],
    include_directories: include_directories('.'),
)
jsonc_validator_dep = declare_dependency(
    include_directories: include_directories('.'),
    link_with: [jsonc_validator],
)
