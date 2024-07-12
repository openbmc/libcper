/**
 * Describes available sections to the CPER parser.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include "../edk/Cper.h"
#include "cper-section.h"
#include "cper-section-arm.h"
#include "cper-section-generic.h"
#include "cper-section-ia32x64.h"
#include "cper-section-ipf.h"
#include "cper-section-memory.h"
#include "cper-section-pcie.h"
#include "cper-section-firmware.h"
#include "cper-section-pci-bus.h"
#include "cper-section-pci-dev.h"
#include "cper-section-dmar-generic.h"
#include "cper-section-dmar-vtd.h"
#include "cper-section-dmar-iommu.h"
#include "cper-section-ccix-per.h"
#include "cper-section-cxl-protocol.h"
#include "cper-section-cxl-component.h"

//Definitions of all sections available to the CPER parser.
CPER_SECTION_DEFINITION section_definitions[] = {
	{ &gEfiProcessorGenericErrorSectionGuid, "Processor Generic",
	  cper_section_generic_to_ir, ir_section_generic_to_cper },
	{ &gEfiIa32X64ProcessorErrorSectionGuid, "IA32/X64",
	  cper_section_ia32x64_to_ir, ir_section_ia32x64_to_cper },
	{ &gEfiIpfProcessorErrorSectionGuid, "IPF", NULL, NULL },
	{ &gEfiArmProcessorErrorSectionGuid, "ARM", cper_section_arm_to_ir,
	  ir_section_arm_to_cper },
	{ &gEfiPlatformMemoryErrorSectionGuid, "Platform Memory",
	  cper_section_platform_memory_to_ir, ir_section_memory_to_cper },
	{ &gEfiPlatformMemoryError2SectionGuid, "Platform Memory 2",
	  cper_section_platform_memory2_to_ir, ir_section_memory2_to_cper },
	{ &gEfiPcieErrorSectionGuid, "PCIe", cper_section_pcie_to_ir,
	  ir_section_pcie_to_cper },
	{ &gEfiFirmwareErrorSectionGuid, "Firmware Error Record Reference",
	  cper_section_firmware_to_ir, ir_section_firmware_to_cper },
	{ &gEfiPciBusErrorSectionGuid, "PCI/PCI-X Bus",
	  cper_section_pci_bus_to_ir, ir_section_pci_bus_to_cper },
	{ &gEfiPciDevErrorSectionGuid, "PCI Component/Device",
	  cper_section_pci_dev_to_ir, ir_section_pci_dev_to_cper },
	{ &gEfiDMArGenericErrorSectionGuid, "DMAr Generic",
	  cper_section_dmar_generic_to_ir, ir_section_dmar_generic_to_cper },
	{ &gEfiDirectedIoDMArErrorSectionGuid,
	  "Intel VT for Directed I/O Specific DMAr",
	  cper_section_dmar_vtd_to_ir, ir_section_dmar_vtd_to_cper },
	{ &gEfiIommuDMArErrorSectionGuid, "IOMMU Specific DMAr",
	  cper_section_dmar_iommu_to_ir, ir_section_dmar_iommu_to_cper },
	{ &gEfiCcixPerLogErrorSectionGuid, "CCIX PER Log Error",
	  cper_section_ccix_per_to_ir, ir_section_ccix_per_to_cper },
	{ &gEfiCxlProtocolErrorSectionGuid, "CXL Protocol Error",
	  cper_section_cxl_protocol_to_ir, ir_section_cxl_protocol_to_cper },
	{ &gEfiCxlGeneralMediaErrorSectionGuid,
	  "CXL General Media Component Error", cper_section_cxl_component_to_ir,
	  ir_section_cxl_component_to_cper },
	{ &gEfiCxlDramEventErrorSectionGuid, "CXL DRAM Component Error",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlMemoryModuleErrorSectionGuid,
	  "CXL Memory Module Component Error", cper_section_cxl_component_to_ir,
	  ir_section_cxl_component_to_cper },
	{ &gEfiCxlPhysicalSwitchErrorSectionGuid,
	  "CXL Physical Switch Component Error",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlVirtualSwitchErrorSectionGuid,
	  "CXL Virtual Switch Component Error",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlMldPortErrorSectionGuid, "CXL MLD Port Component Error",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
};
const size_t section_definitions_len =
	sizeof(section_definitions) / sizeof(CPER_SECTION_DEFINITION);
