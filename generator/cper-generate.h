#ifndef CPER_GENERATE_H
#define CPER_GENERATE_H

#include "../edk/BaseTypes.h"

#include <stdio.h>

void generate_cper_record(char** types, UINT16 num_sections, FILE* out);
void generate_single_section_record(char* type, FILE* out);

#endif
