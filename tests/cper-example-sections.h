#ifndef CPER_EXAMPLE_SECTIONS_H
#define CPER_EXAMPLE_SECTIONS_H

/*
 * List of CPER example sections that have a fixed binary file
 * (examples/<name>.cperhex) and a golden JSON representation
 * (examples/<name>.json).
 *
 * This is the single source of truth shared by the C test suite
 * (tests/ir-tests.c) and the C++ bindings test suite
 * (tests/cxx/ir.cpp). It expands to the comma-separated
 * contents of an initializer list, so it can be used to build either a C
 * array or a C++ std::array.
 *
 * Keep this in sync with the examples/ directory.
 */
// clang-format off
#define CPER_EXAMPLE_SECTIONS                                    \
    "arm",                                                       \
    "arm-ras",                                                   \
    "ccixper",                                                   \
    "cxlcomponent-media",                                        \
    "cxlprotocol",                                               \
    "dmargeneric",                                               \
    "dmariommu",                                                 \
    "dmarvtd",                                                   \
    "firmware",                                                  \
    "generic",                                                   \
    "ia32x64",                                                   \
    "memory",                                                    \
    "memory-validation-bits",                                    \
    "memory2",                                                   \
    "nvidia",                                                    \
    "nvidia_cmet_info",                                          \
    "nvidia_event_all_types",                                    \
    "nvidia_event_gpu_init",                                     \
    "nvidia_event_gpu_uce_ecc",                                  \
    "pcibus",                                                    \
    "pcidev",                                                    \
    "pcie",                                                      \
    "unknown"
// clang-format on

#endif // CPER_EXAMPLE_SECTIONS_H
