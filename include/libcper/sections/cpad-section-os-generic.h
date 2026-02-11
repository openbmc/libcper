#ifndef CPER_SECTION_GENERIC_H
#define CPER_SECTION_GENERIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <json.h>
#include <libcper/Cpad.h>


json_object *cpad_section_os_generic_to_ir(const UINT8 *section, UINT32 size);
void ir_section_os_generic_to_cpad(json_object *section_ir, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
