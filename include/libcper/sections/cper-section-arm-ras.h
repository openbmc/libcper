#ifndef CPER_SECTION_ARM_RAS_H
#define CPER_SECTION_ARM_RAS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

#define ARM_RAS_COMPONENT_TYPE_KEYS                                            \
	(int[]){ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }
#define ARM_RAS_COMPONENT_TYPE_VALUES                                          \
	(const char *[]){ "Processor error node", "Memory error node",         \
			  "SMMU error node",	  "Vendor-defined error node", \
			  "GIC error node",	  "PCIe error node",           \
			  "Proxy error node" }
#define ARM_RAS_COMPONENT_TYPE_COUNT 7

#define ARM_RAS_IP_INSTANCE_FORMAT_KEYS (int[]){ 0x00, 0x01, 0x02, 0x03 }
#define ARM_RAS_IP_INSTANCE_FORMAT_VALUES                                      \
	(const char *[]){ "PE", "System Physical Address (SPA)",               \
			  "Local Address ID", "SoC-specific ID" }
#define ARM_RAS_IP_INSTANCE_FORMAT_COUNT 4

#define ARM_RAS_IP_TYPE_FORMAT_KEYS (int[]){ 0x00, 0x01, 0x02, 0x03, 0xFF }
#define ARM_RAS_IP_TYPE_FORMAT_VALUES                                          \
	(const char *[]){ "PE", "SMMU IIDR", "GIC IIDR (GICD IIDR for GICv3)", \
			  "PIDR", "Invalid IP_type" }
#define ARM_RAS_IP_TYPE_FORMAT_COUNT 5

json_object *cper_section_arm_ras_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string);
void ir_section_arm_ras_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
