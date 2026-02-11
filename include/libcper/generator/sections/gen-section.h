// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#ifndef GEN_SECTIONS_H
#define GEN_SECTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <libcper/Cper.h>

// Run tests with some or all validation bits set.
typedef enum { SOME_VALID, RANDOM_VALID, ALL_VALID } GEN_VALID_BITS_TEST_TYPE;

//Section generator function predefinitions.
size_t generate_section_generic(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_ia32x64(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_arm(void **location,
			    GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_arm_ras(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_memory(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_memory2(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_pcie(void **location,
			     GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_pci_bus(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_pci_dev(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_firmware(void **location,
				 GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_dmar_generic(void **location,
				     GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_dmar_vtd(void **location,
				 GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_dmar_iommu(void **location,
				   GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_ccix_per(void **location,
				 GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_cxl_protocol(void **location,
				     GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_cxl_component(void **location,
				      GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_nvidia(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_nvidia_events(void **location,
				      GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_ampere(void **location,
			       GEN_VALID_BITS_TEST_TYPE validBitsType);
size_t generate_section_info_ppr(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType);

//Definition structure for a single CPER section generator.
typedef struct {
	EFI_GUID *Guid;
	const char *ShortName;
	size_t (*Generate)(void **, GEN_VALID_BITS_TEST_TYPE);
} CPER_GENERATOR_DEFINITION;

extern CPER_GENERATOR_DEFINITION generator_definitions[];
extern const size_t generator_definitions_len;

#ifdef __cplusplus
}
#endif

#endif
