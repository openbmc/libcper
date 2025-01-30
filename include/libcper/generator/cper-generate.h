#ifndef CPER_GENERATE_H
#define CPER_GENERATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/sections/gen-section.h>

void generate_cper_record(char **types, UINT16 num_sections, FILE *out,
			  GEN_VALID_BITS_TEST_TYPE validBitsType);
void generate_single_section_record(char *type, FILE *out,
				    GEN_VALID_BITS_TEST_TYPE validBitsType);

#ifdef __cplusplus
}
#endif

#endif
