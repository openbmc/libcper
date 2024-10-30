/**
 * Describes available section generators to the CPER generator.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include "gen-section.h"

CPER_GENERATOR_DEFINITION generator_definitions[] = {
	{ &gEfiProcessorGenericErrorSectionGuid, "generic",
	  generate_section_generic },
	{ &gEfiIa32X64ProcessorErrorSectionGuid, "ia32x64",
	  generate_section_ia32x64 },
	{ &gEfiArmProcessorErrorSectionGuid, "arm", generate_section_arm },
	{ &gEfiPlatformMemoryErrorSectionGuid, "memory",
	  generate_section_memory },
	{ &gEfiPlatformMemoryError2SectionGuid, "memory2",
	  generate_section_memory2 },
	{ &gEfiPcieErrorSectionGuid, "pcie", generate_section_pcie },
	{ &gEfiFirmwareErrorSectionGuid, "firmware",
	  generate_section_firmware },
	{ &gEfiPciBusErrorSectionGuid, "pcibus", generate_section_pci_bus },
	{ &gEfiPciDevErrorSectionGuid, "pcidev", generate_section_pci_dev },
	{ &gEfiDMArGenericErrorSectionGuid, "dmargeneric",
	  generate_section_dmar_generic },
	{ &gEfiDirectedIoDMArErrorSectionGuid, "dmarvtd",
	  generate_section_dmar_vtd },
	{ &gEfiIommuDMArErrorSectionGuid, "dmariommu",
	  generate_section_dmar_iommu },
	{ &gEfiCcixPerLogErrorSectionGuid, "ccixper",
	  generate_section_ccix_per },
	{ &gEfiCxlProtocolErrorSectionGuid, "cxlprotocol",
	  generate_section_cxl_protocol },
	{ &gEfiCxlGeneralMediaErrorSectionGuid, "cxlcomponent-media",
	  generate_section_cxl_component },
	{ &gEfiCxlDramEventErrorSectionGuid, "cxlcomponent-dram",
	  generate_section_cxl_component },
	{ &gEfiCxlMemoryModuleErrorSectionGuid, "cxlcomponent-memory",
	  generate_section_cxl_component },
	{ &gEfiCxlPhysicalSwitchErrorSectionGuid, "cxlcomponent-pswitch",
	  generate_section_cxl_component },
	{ &gEfiCxlVirtualSwitchErrorSectionGuid, "cxlcomponent-vswitch",
	  generate_section_cxl_component },
	{ &gEfiCxlMldPortErrorSectionGuid, "cxlcomponent-mld",
	  generate_section_cxl_component },
	{ &gEfiNvidiaErrorSectionGuid, "nvidia", generate_section_nvidia },
	{ &gEfiAmpereErrorSectionGuid, "ampere", generate_section_ampere },
	{ &gEfiAmdFatalErrorSectionGuid, "amd-fatalerror", generate_section_fatal_amd },
};
const size_t generator_definitions_len =
	sizeof(generator_definitions) / sizeof(CPER_GENERATOR_DEFINITION);
