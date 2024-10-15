#ifndef CPER_PARSE_STR_H
#define CPER_PARSE_STR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *cperbuf_to_str_ir(const unsigned char *cper, size_t size);
char *cperbuf_single_section_to_str_ir(const unsigned char *cper_section,
				       size_t size);

#ifdef __cplusplus
}
#endif

#endif
