#ifndef CPER_GENERATE_H
#define CPER_GENERATE_H

#include <stdio.h>
#include "../edk/BaseTypes.h"

void generate_cper_record(char** types, UINT16 num_sections, FILE* cper_file);

#endif