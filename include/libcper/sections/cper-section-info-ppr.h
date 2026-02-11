#ifndef CPER_SECTION_INFO_PPR
#define CPER_SECTION_INFO_PPR

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <libcper/Cper.h>

json_object *cper_section_info_ppr_to_ir(const UINT8 *section, UINT32 size);
void ir_section_info_ppr_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
