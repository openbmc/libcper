#ifndef CPAD_PARSE_H
#define CPAD_PARSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>
#include <stdio.h>

#define CPER_HEADER_VALID_BITFIELD_NAMES                                       \
	(const char *[]){ "platformIDValid", "timestampValid",                 \
			  "partitionIDValid" }
#define CPAD_SECTION_DESCRIPTOR_VALID_BITFIELD_NAMES                           \
	(const char *[]){ "fruIDValid", "fruStringValid" }
#define CPAD_URGENCY_BITFIELD_NAMES                                        \
    (const char *[]){ "high" }
#define CPAD_SECTION_DESCRIPTOR_FLAGS_BITFIELD_NAMES                           \
	(const char *[]){ "reserved" }
#define CPAD_SECTION_DESCRIPTOR_FLAGS_NAMES_COUNT 1
#define CPAD_HEADER_FLAG_TYPES_KEYS (int[]){ 1 }
#define CPAD_HEADER_FLAG_TYPES_VALUES                                          \
	(const char *[]){ "Reserved" }

int cpad_header_valid(const char *cpad_buf, size_t size);

json_object *cpad_to_ir(FILE *cpad_file);
json_object *cpad_buf_to_ir(const unsigned char *cpad_buf, size_t size);
json_object *cpad_single_section_to_ir(FILE *cpad_section_file);
json_object *cpad_buf_single_section_to_ir(const unsigned char *cpad_buf,
					   size_t size);

void ir_to_cpad(json_object *ir, FILE *out);
void ir_single_section_to_cpad(json_object *ir, FILE *out);
#ifdef __cplusplus
}
#endif

#endif
