#ifndef CPER_SECTION_DMAR_IOMMU_H
#define CPER_SECTION_DMAR_IOMMU_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

json_object *cper_section_dmar_iommu_to_ir(const UINT8 *section, UINT32 size,
					   char **desc_string);
void ir_section_dmar_iommu_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
