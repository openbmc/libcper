#ifndef CPAD_GENERATE_H
#define CPAD_GENERATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/sections/gen-section.h>

void generate_cpad_record(char **types, UINT16 *action_ids, UINT16 num_sections,
			  FILE *out);
void generate_single_cpad_section_record(char *type, UINT16 action_id,
					 FILE *out);

#ifdef __cplusplus
}
#endif

#endif // CPAD_GENERATE_H
