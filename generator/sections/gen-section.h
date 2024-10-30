#ifndef GEN_SECTIONS_H
#define GEN_SECTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "../../edk/Cper.h"

//Section generator function predefinitions.
size_t generate_section_generic(void **location);
size_t generate_section_ia32x64(void **location);
size_t generate_section_arm(void **location);
size_t generate_section_memory(void **location);
size_t generate_section_memory2(void **location);
size_t generate_section_pcie(void **location);
size_t generate_section_pci_bus(void **location);
size_t generate_section_pci_dev(void **location);
size_t generate_section_firmware(void **location);
size_t generate_section_dmar_generic(void **location);
size_t generate_section_dmar_vtd(void **location);
size_t generate_section_dmar_iommu(void **location);
size_t generate_section_ccix_per(void **location);
size_t generate_section_cxl_protocol(void **location);
size_t generate_section_cxl_component(void **location);
size_t generate_section_nvidia(void **location);
size_t generate_section_ampere(void **location);
size_t generate_section_fatal_amd(void **location);

//Definition structure for a single CPER section generator.
typedef struct {
	EFI_GUID *Guid;
	const char *ShortName;
	size_t (*Generate)(void **);
} CPER_GENERATOR_DEFINITION;

extern CPER_GENERATOR_DEFINITION generator_definitions[];
extern const size_t generator_definitions_len;

#ifdef __cplusplus
}
#endif

#endif
