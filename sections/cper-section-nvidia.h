#ifndef CPER_SECTION_NVIDIA_H
#define CPER_SECTION_NVIDIA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include "../edk/Cper.h"

json_object *cper_section_nvidia_to_ir(void *section);
void ir_section_nvidia_to_cper(json_object *section, FILE *out);

#ifdef __cplusplus
}
#endif

#endif
