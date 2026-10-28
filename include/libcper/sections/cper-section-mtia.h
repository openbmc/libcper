#ifndef CPER_SECTION_MTIA_H
#define CPER_SECTION_MTIA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

json_object *cper_section_mtia_to_ir(const UINT8 *section, UINT32 size,
				     char **desc_string);
void ir_section_mtia_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
