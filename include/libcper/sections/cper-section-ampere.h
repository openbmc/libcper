#ifndef CPER_SECTION_AMPERE_H
#define CPER_SECTION_AMPERE_H

#include <stdio.h>
#include <json.h>
#include <libcper/Cper.h>

json_object *cper_section_ampere_to_ir(void *section);
void ir_section_ampere_to_cper(json_object *section, FILE *out);

#endif
