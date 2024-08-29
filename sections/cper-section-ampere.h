#ifndef CPER_SECTION_AMPERE_H
#define CPER_SECTION_AMPERE_H

#include <json.h>
#include "../edk/Cper.h"

typedef struct {
	UINT16 type_id;
	UINT16 sub_type_id;
	UINT32 instance_id;
} __attribute__((packed)) EFI_AMPERE_ERROR_RECORD;

json_object *cper_section_ampere_to_ir(void *section);
void ir_section_ampere_to_cper(json_object *section, FILE *out);

#endif
