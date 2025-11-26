/**
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * Describes available sections to the CPER parser.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include <libcper/Cper.h>
#include <libcper/sections/cper-section.h>
#include <libcper/sections/cper-section-arm.h>
#include <libcper/sections/cper-section-arm-ras.h>
#include <libcper/sections/cper-section-generic.h>
#include <libcper/sections/cper-section-ia32x64.h>
#include <libcper/sections/cper-section-ipf.h>
#include <libcper/sections/cper-section-memory.h>
#include <libcper/sections/cper-section-pcie.h>
#include <libcper/sections/cper-section-firmware.h>
#include <libcper/sections/cper-section-pci-bus.h>
#include <libcper/sections/cper-section-pci-dev.h>
#include <libcper/sections/cper-section-dmar-generic.h>
#include <libcper/sections/cper-section-dmar-vtd.h>
#include <libcper/sections/cper-section-dmar-iommu.h>
#include <libcper/sections/cper-section-ccix-per.h>
#include <libcper/sections/cper-section-cxl-protocol.h>
#include <libcper/sections/cper-section-cxl-component.h>
#include <libcper/sections/cper-section-nvidia.h>
#include <libcper/sections/cper-section-nvidia-events.h>
#include <libcper/sections/cper-section-ampere.h>

//Definitions of all sections available to the CPER parser.
CPER_SECTION_DEFINITION section_definitions[] = {
	{ &gEfiProcessorGenericErrorSectionGuid, "Processor Generic",
	  "GenericProcessor", cper_section_generic_to_ir,
	  ir_section_generic_to_cper },
	{ &gEfiIa32X64ProcessorErrorSectionGuid, "IA32/X64", "Ia32x64Processor",
	  cper_section_ia32x64_to_ir, ir_section_ia32x64_to_cper },
	{ &gEfiIpfProcessorErrorSectionGuid, "IPF", "IPF", NULL, NULL },
	{ &gEfiArmProcessorErrorSectionGuid, "ARM", "ArmProcessor",
	  cper_section_arm_to_ir, ir_section_arm_to_cper },
	{ &gEfiArmRasNodeSectionGuid, "ARM RAS", "ArmRas",
	  cper_section_arm_ras_to_ir, ir_section_arm_ras_to_cper },
	{ &gEfiPlatformMemoryErrorSectionGuid, "Platform Memory", "Memory",
	  cper_section_platform_memory_to_ir, ir_section_memory_to_cper },
	{ &gEfiPlatformMemoryError2SectionGuid, "Platform Memory 2", "Memory2",
	  cper_section_platform_memory2_to_ir, ir_section_memory2_to_cper },
	{ &gEfiPcieErrorSectionGuid, "PCIe", "Pcie", cper_section_pcie_to_ir,
	  ir_section_pcie_to_cper },
	{ &gEfiFirmwareErrorSectionGuid, "Firmware Error Record Reference",
	  "Firmware", cper_section_firmware_to_ir,
	  ir_section_firmware_to_cper },
	{ &gEfiPciBusErrorSectionGuid, "PCI/PCI-X Bus", "PciBus",
	  cper_section_pci_bus_to_ir, ir_section_pci_bus_to_cper },
	{ &gEfiPciDevErrorSectionGuid, "PCI Component/Device", "PciComponent",
	  cper_section_pci_dev_to_ir, ir_section_pci_dev_to_cper },
	{ &gEfiDMArGenericErrorSectionGuid, "DMAr Generic", "GenericDmar",
	  cper_section_dmar_generic_to_ir, ir_section_dmar_generic_to_cper },
	{ &gEfiDirectedIoDMArErrorSectionGuid,
	  "Intel VT for Directed I/O Specific DMAr", "VtdDmar",
	  cper_section_dmar_vtd_to_ir, ir_section_dmar_vtd_to_cper },
	{ &gEfiIommuDMArErrorSectionGuid, "IOMMU Specific DMAr", "IommuDmar",
	  cper_section_dmar_iommu_to_ir, ir_section_dmar_iommu_to_cper },
	{ &gEfiCcixPerLogErrorSectionGuid, "CCIX PER Log Error", "CcixPer",
	  cper_section_ccix_per_to_ir, ir_section_ccix_per_to_cper },
	{ &gEfiCxlProtocolErrorSectionGuid, "CXL Protocol Error", "CxlProtocol",
	  cper_section_cxl_protocol_to_ir, ir_section_cxl_protocol_to_cper },
	{ &gEfiCxlGeneralMediaErrorSectionGuid,
	  "CXL General Media Component Error", "CxlComponent",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlDramEventErrorSectionGuid, "CXL DRAM Component Error",
	  "CxlComponent", cper_section_cxl_component_to_ir,
	  ir_section_cxl_component_to_cper },
	{ &gEfiCxlMemoryModuleErrorSectionGuid,
	  "CXL Memory Module Component Error", "CxlComponent",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlPhysicalSwitchErrorSectionGuid,
	  "CXL Physical Switch Component Error", "CxlComponent",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlVirtualSwitchErrorSectionGuid,
	  "CXL Virtual Switch Component Error", "CxlComponent",
	  cper_section_cxl_component_to_ir, ir_section_cxl_component_to_cper },
	{ &gEfiCxlMldPortErrorSectionGuid, "CXL MLD Port Component Error",
	  "CxlComponent", cper_section_cxl_component_to_ir,
	  ir_section_cxl_component_to_cper },
	{ &gEfiNvidiaErrorSectionGuid, "NVIDIA", "Nvidia",
	  cper_section_nvidia_to_ir, ir_section_nvidia_to_cper },
	{ &gEfiNvidiaEventErrorSectionGuid, "NvidiaEvent", "NvidiaEvent",
	  cper_section_nvidia_events_to_ir, ir_section_nvidia_events_to_cper },
	{ &gEfiAmpereErrorSectionGuid, "Ampere", "Ampere",
	  cper_section_ampere_to_ir, ir_section_ampere_to_cper },
};
const size_t section_definitions_len =
	sizeof(section_definitions) / sizeof(CPER_SECTION_DEFINITION);
