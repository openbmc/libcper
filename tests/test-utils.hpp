#ifndef CPER_IR_TEST_UTILS_H
#define CPER_IR_TEST_UTILS_H

extern "C" {
#include <stdio.h>
#include <libcper/BaseTypes.h>
}

FILE *generate_record_memstream(const char **types, UINT16 num_types,
				char **buf, size_t *buf_size,
				int single_section);

#endif
