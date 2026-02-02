#ifndef CPER_UTILS_H
#define CPER_UTILS_H

#define GUID_STRING_LENGTH 36
#define TIMESTAMP_LENGTH   26

#ifdef __cplusplus
extern "C" {
#endif

#include <libcper/common-utils.h>
#include <libcper/Cper.h>
#include <json.h>
#include <stdbool.h>

typedef enum { UINT_8T, UINT_16T, UINT_32T, UINT_64T } IntType;

typedef struct {
	IntType size;
	union {
		UINT8 ui8;
		UINT16 ui16;
		UINT32 ui32;
		UINT64 ui64;
	} value;
} ValidationTypes;

json_object *
cper_generic_error_status_to_ir(EFI_GENERIC_ERROR_STATUS *error_status);
void ir_generic_error_status_to_cper(
	json_object *error_status, EFI_GENERIC_ERROR_STATUS *error_status_cper);
json_object *uniform_struct_to_ir(UINT32 *start, int len, const char *names[]);
json_object *uniform_struct64_to_ir(UINT64 *start, int len,
				    const char *names[]);
void ir_to_uniform_struct(json_object *ir, UINT32 *start, int len,
			  const char *names[]);
void ir_to_uniform_struct64(json_object *ir, UINT64 *start, int len,
			    const char *names[]);
json_object *integer_to_readable_pair(UINT64 value, int len, const int keys[],
				      const char *values[],
				      const char *default_value);
json_object *integer_to_readable_pair_with_desc(int value, int len,
						const int keys[],
						const char *values[],
						const char *descriptions[],
						const char *default_value);
UINT64 readable_pair_to_integer(json_object *pair);
json_object *bitfield_to_ir(UINT64 bitfield, int num_fields,
			    const char *names[]);
UINT64 ir_to_bitfield(json_object *ir, int num_fields, const char *names[]);
bool isvalid_prop_to_ir(ValidationTypes *val, int vbit_idx);
void add_to_valid_bitfield(ValidationTypes *val, int vbit_idx);
void print_val(ValidationTypes *val);
json_object *uint64_array_to_ir_array(UINT64 *array, int len);
json_object *revision_to_ir(UINT16 revision);
const char *severity_to_string(UINT32 severity);
int timestamp_to_string(char *out, int out_len,
			EFI_ERROR_TIME_STAMP *timestamp);
void string_to_timestamp(EFI_ERROR_TIME_STAMP *out, const char *timestamp);
int guid_to_string(char *out, size_t out_len, EFI_GUID *guid);
void string_to_guid(EFI_GUID *out, const char *guid);
int guid_equal(EFI_GUID *a, EFI_GUID *b);
int select_guid_from_list(EFI_GUID *guid, EFI_GUID *guid_list[], int len);

int cper_printable_string_length(const char *str, int number_chars);

void add_untrusted_string(json_object *ir, const char *field_name,
			  const char *str, int len);

void add_guid(json_object *ir, const char *field_name, EFI_GUID *guid);

void add_string(json_object *register_ir, const char *field_name,
		const char *value);
void add_string_len(json_object *register_ir, const char *field_name,
		    const char *value, int len);
void add_int(json_object *register_ir, const char *field_name, int64_t value);
void add_uint(json_object *register_ir, const char *field_name, uint64_t value);

void add_int_hex(json_object *register_ir, const char *field_name,
		 UINT64 value);
void add_int_hex_8(json_object *register_ir, const char *field_name,
		   UINT8 value);
void add_int_hex_16(json_object *register_ir, const char *field_name,
		    UINT16 value);
void add_int_hex_24(json_object *register_ir, const char *field_name,
		    UINT64 value);
void add_int_hex_64(json_object *register_ir, const char *field_name,
		    UINT64 value);

void add_bool(json_object *register_ir, const char *field_name, UINT64 value);

void add_bool_enum(json_object *register_ir, const char *field_name,
		   const char *value_dict[2], UINT64 value);

void add_dict(json_object *register_ir, const char *field_name, UINT64 value,
	      const char *dict[], size_t dict_size);

//The available severity types for CPER.
extern const char *CPER_SEVERITY_TYPES[4];

#ifdef __cplusplus
}
#endif

#endif
