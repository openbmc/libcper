/**
 * Describes utility functions for parsing CPER into JSON IR.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <ctype.h>
#include <stdio.h>
#include <json.h>
#include <string.h>
#include <libcper/Cper.h>
#include <libcper/cper-utils.h>
#include <libcper/log.h>

//The available severity types for CPER.
const char *CPER_SEVERITY_TYPES[4] = { "Recoverable", "Fatal", "Corrected",
				       "Informational" };

//Converts the given generic CPER error status to JSON IR.
json_object *
cper_generic_error_status_to_ir(EFI_GENERIC_ERROR_STATUS *error_status)
{
	json_object *error_status_ir = json_object_new_object();

	//Error type.
	json_object_object_add(error_status_ir, "errorType",
			       integer_to_readable_pair_with_desc(
				       error_status->Type, 18,
				       CPER_GENERIC_ERROR_TYPES_KEYS,
				       CPER_GENERIC_ERROR_TYPES_VALUES,
				       CPER_GENERIC_ERROR_TYPES_DESCRIPTIONS,
				       "Unknown (Reserved)"));

	//Boolean bit fields.
	json_object_object_add(
		error_status_ir, "addressSignal",
		json_object_new_boolean(error_status->AddressSignal));
	json_object_object_add(
		error_status_ir, "controlSignal",
		json_object_new_boolean(error_status->ControlSignal));
	json_object_object_add(
		error_status_ir, "dataSignal",
		json_object_new_boolean(error_status->DataSignal));
	json_object_object_add(
		error_status_ir, "detectedByResponder",
		json_object_new_boolean(error_status->DetectedByResponder));
	json_object_object_add(
		error_status_ir, "detectedByRequester",
		json_object_new_boolean(error_status->DetectedByRequester));
	json_object_object_add(
		error_status_ir, "firstError",
		json_object_new_boolean(error_status->FirstError));
	json_object_object_add(
		error_status_ir, "overflowDroppedLogs",
		json_object_new_boolean(error_status->OverflowNotLogged));

	return error_status_ir;
}

//Converts the given CPER-JSON generic error status into a CPER structure.
void ir_generic_error_status_to_cper(
	json_object *error_status, EFI_GENERIC_ERROR_STATUS *error_status_cper)
{
	error_status_cper->Type = readable_pair_to_integer(
		json_object_object_get(error_status, "errorType"));
	error_status_cper->AddressSignal = json_object_get_boolean(
		json_object_object_get(error_status, "addressSignal"));
	error_status_cper->ControlSignal = json_object_get_boolean(
		json_object_object_get(error_status, "controlSignal"));
	error_status_cper->DataSignal = json_object_get_boolean(
		json_object_object_get(error_status, "dataSignal"));
	error_status_cper->DetectedByResponder = json_object_get_boolean(
		json_object_object_get(error_status, "detectedByResponder"));
	error_status_cper->DetectedByRequester = json_object_get_boolean(
		json_object_object_get(error_status, "detectedByRequester"));
	error_status_cper->FirstError = json_object_get_boolean(
		json_object_object_get(error_status, "firstError"));
	error_status_cper->OverflowNotLogged = json_object_get_boolean(
		json_object_object_get(error_status, "overflowDroppedLogs"));
}

//Converts a single uniform struct of UINT64s into intermediate JSON IR format, given names for each field in byte order.
json_object *uniform_struct64_to_ir(UINT64 *start, int len, const char *names[])
{
	json_object *result = json_object_new_object();

	UINT64 *cur = start;
	for (int i = 0; i < len; i++) {
		json_object_object_add(result, names[i],
				       json_object_new_uint64(*cur));
		cur++;
	}

	return result;
}

//Converts a single uniform struct of UINT32s into intermediate JSON IR format, given names for each field in byte order.
json_object *uniform_struct_to_ir(UINT32 *start, int len, const char *names[])
{
	json_object *result = json_object_new_object();

	UINT32 *cur = start;
	for (int i = 0; i < len; i++) {
		UINT32 value;
		memcpy(&value, cur, sizeof(UINT32));
		json_object_object_add(result, names[i],
				       json_object_new_uint64(value));
		cur++;
	}

	return result;
}

//Converts a single object containing UINT32s into a uniform struct.
void ir_to_uniform_struct64(json_object *ir, UINT64 *start, int len,
			    const char *names[])
{
	UINT64 *cur = start;
	for (int i = 0; i < len; i++) {
		*cur = json_object_get_uint64(
			json_object_object_get(ir, names[i]));
		cur++;
	}
}

//Converts a single object containing UINT32s into a uniform struct.
void ir_to_uniform_struct(json_object *ir, UINT32 *start, int len,
			  const char *names[])
{
	UINT32 *cur = start;
	for (int i = 0; i < len; i++) {
		*cur = (UINT32)json_object_get_uint64(
			json_object_object_get(ir, names[i]));
		cur++;
	}
}

//Converts a single integer value to an object containing a value, and a readable name if possible.
json_object *integer_to_readable_pair(UINT64 value, int len, const int keys[],
				      const char *values[],
				      const char *default_value)
{
	json_object *result = json_object_new_object();
	json_object_object_add(result, "value", json_object_new_uint64(value));

	//Search for human readable name, add.
	const char *name = default_value;
	for (int i = 0; i < len; i++) {
		if ((UINT64)keys[i] == value) {
			name = values[i];
		}
	}

	json_object_object_add(result, "name", json_object_new_string(name));
	return result;
}

//Converts a single integer value to an object containing a value, readable name and description if possible.
json_object *integer_to_readable_pair_with_desc(int value, int len,
						const int keys[],
						const char *values[],
						const char *descriptions[],
						const char *default_value)
{
	json_object *result = json_object_new_object();
	json_object_object_add(result, "value", json_object_new_int(value));

	//Search for human readable name, add.
	const char *name = default_value;
	for (int i = 0; i < len; i++) {
		if (keys[i] == value) {
			name = values[i];
			json_object_object_add(
				result, "description",
				json_object_new_string(descriptions[i]));
		}
	}

	json_object_object_add(result, "name", json_object_new_string(name));
	return result;
}

//Returns a single UINT64 value from the given readable pair object.
//Assumes the integer value is held in the "value" field.
UINT64 readable_pair_to_integer(json_object *pair)
{
	return json_object_get_uint64(json_object_object_get(pair, "value"));
}

//Converts the given 64 bit bitfield to IR, assuming bit 0 starts on the left.
json_object *bitfield_to_ir(UINT64 bitfield, int num_fields,
			    const char *names[])
{
	json_object *result = json_object_new_object();
	for (int i = 0; i < num_fields; i++) {
		json_object_object_add(result, names[i],
				       json_object_new_boolean((bitfield >> i) &
							       0x1));
	}

	return result;
}

//Filters properties based on Validation Bits.
// Refer to CPER spec for vbit_idx to be passed here.
void add_to_valid_bitfield(ValidationTypes *val, int vbit_idx)
{
	switch (val->size) {
	case UINT_8T:
		val->value.ui8 |= (0x01 << vbit_idx);
		break;
	case UINT_16T:
		val->value.ui16 |= (0x01 << vbit_idx);
		break;
	case UINT_32T:
		val->value.ui32 |= (0x01 << vbit_idx);
		break;
	case UINT_64T:
		val->value.ui64 |= (0x01 << vbit_idx);
		break;
	default:
		cper_print_log(
			"IR to CPER: Unknown validation bits size passed, Enum IntType=%d",
			val->size);
	}
}

//Converts the given IR bitfield into a standard UINT64 bitfield, with fields beginning from bit 0.
UINT64 ir_to_bitfield(json_object *ir, int num_fields, const char *names[])
{
	UINT64 result = 0x0;
	for (int i = 0; i < num_fields; i++) {
		if (json_object_get_boolean(
			    json_object_object_get(ir, names[i]))) {
			result |= (0x1 << i);
		}
	}

	return result;
}

// Filters properties based on Validation Bits.
// Refer to CPER spec for vbit_idx to be passed here.
// Overload function for 16, 32, 64b
bool isvalid_prop_to_ir(ValidationTypes *val, int vbit_idx)
{
// If the option is enabled, output invalid properties
// as well as valid ones.
#ifdef OUTPUT_ALL_PROPERTIES
	return true;
#endif //OUTPUT_ALL_PROPERTIES
	UINT64 vbit_mask = 0x01 << vbit_idx;
	switch (val->size) {
	case UINT_16T:
		return (vbit_mask & val->value.ui16);

	case UINT_32T:
		return (vbit_mask & val->value.ui32);

	case UINT_64T:
		return (vbit_mask & val->value.ui64);

	default:
		cper_print_log(
			"CPER to IR:Unknown validation bits size passed. Enum IntType: %d",
			val->size);
	}
	return 0;
}

void print_val(ValidationTypes *val)
{
	switch (val->size) {
	case UINT_8T:
		cper_print_log("Validation bits: %x\n", val->value.ui8);
		break;
	case UINT_16T:
		cper_print_log("Validation bits: %x\n", val->value.ui16);
		break;

	case UINT_32T:
		cper_print_log("Validation bits: %x\n", val->value.ui32);
		break;

	case UINT_64T:
		cper_print_log("Validation bits: %llx\n", val->value.ui64);
		break;

	default:
		cper_print_log(
			"CPER to IR:Unknown validation bits size passed. Enum IntType: %d",
			val->size);
	}
}

//Converts the given UINT64 array into a JSON IR array, given the length.
json_object *uint64_array_to_ir_array(UINT64 *array, int len)
{
	json_object *array_ir = json_object_new_array();
	for (int i = 0; i < len; i++) {
		json_object_array_add(array_ir,
				      json_object_new_uint64(array[i]));
	}
	return array_ir;
}

//Converts a single UINT16 revision number into JSON IR representation.
json_object *revision_to_ir(UINT16 revision)
{
	json_object *revision_info = json_object_new_object();
	json_object_object_add(revision_info, "major",
			       json_object_new_int(revision >> 8));
	json_object_object_add(revision_info, "minor",
			       json_object_new_int(revision & 0xFF));
	return revision_info;
}

//Returns the appropriate string for the given integer severity.
const char *severity_to_string(UINT32 severity)
{
	return severity < 4 ? CPER_SEVERITY_TYPES[severity] : "Unknown";
}

//Converts a single EFI timestamp to string, at the given output.
//Output must be at least TIMESTAMP_LENGTH bytes long.
int timestamp_to_string(char *out, int out_len, EFI_ERROR_TIME_STAMP *timestamp)
{
	//Cannot go to three digits.
	int century = bcd_to_int(timestamp->Century) % 100;
	if (century >= 100) {
		return -1;
	}
	int year = bcd_to_int(timestamp->Year) % 100;
	if (year >= 100) {
		return -1;
	}
	int month = bcd_to_int(timestamp->Month);
	if (month > 12) {
		return -1;
	}
	int day = bcd_to_int(timestamp->Day);
	if (day > 31) {
		return -1;
	}
	int hours = bcd_to_int(timestamp->Hours);
	if (hours > 24) {
		return -1;
	}
	int minutes = bcd_to_int(timestamp->Minutes);
	if (minutes > 60) {
		return -1;
	}
	int seconds = bcd_to_int(timestamp->Seconds);
	if (seconds >= 60) {
		return -1;
	}
	int written = snprintf(
		out, out_len,
		"%02hhu%02hhu-%02hhu-%02hhuT%02hhu:%02hhu:%02hhu+00:00",
		century, year, month, day, hours, minutes, seconds);

	if (written < 0 || written >= out_len) {
		cper_print_log("Timestamp buffer of insufficient size\n");
		return -1;
	}
	return 0;
}

//Converts a single timestamp string to an EFI timestamp.
void string_to_timestamp(EFI_ERROR_TIME_STAMP *out, const char *timestamp)
{
	//Ignore invalid timestamps.
	if (timestamp == NULL) {
		return;
	}

	sscanf(timestamp, "%2hhu%2hhu-%hhu-%hhuT%hhu:%hhu:%hhu+00:00",
	       &out->Century, &out->Year, &out->Month, &out->Day, &out->Hours,
	       &out->Minutes, &out->Seconds);

	//Convert back to BCD.
	out->Century = int_to_bcd(out->Century);
	out->Year = int_to_bcd(out->Year);
	out->Month = int_to_bcd(out->Month);
	out->Day = int_to_bcd(out->Day);
	out->Hours = int_to_bcd(out->Hours);
	out->Minutes = int_to_bcd(out->Minutes);
	out->Seconds = int_to_bcd(out->Seconds);
}

//Helper function to convert an EDK EFI GUID into a string for intermediate use.
int guid_to_string(char *out, size_t out_len, EFI_GUID *guid)
{
	size_t len = snprintf(
		out, out_len,
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", guid->Data1,
		guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1],
		guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5],
		guid->Data4[6], guid->Data4[7]);
	if (len != out_len) {
		return -1;
	}
	return len;
}

//Helper function to convert a string into an EDK EFI GUID.
void string_to_guid(EFI_GUID *out, const char *guid)
{
	//Ignore invalid GUIDs.
	if (guid == NULL) {
		return;
	}

	sscanf(guid,
	       "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	       &out->Data1, &out->Data2, &out->Data3, out->Data4,
	       out->Data4 + 1, out->Data4 + 2, out->Data4 + 3, out->Data4 + 4,
	       out->Data4 + 5, out->Data4 + 6, out->Data4 + 7);
}

//Returns one if two EFI GUIDs are equal, zero otherwise.
int guid_equal(EFI_GUID *a, EFI_GUID *b)
{
	//Check top base 3 components.
	if (a->Data1 != b->Data1 || a->Data2 != b->Data2 ||
	    a->Data3 != b->Data3) {
		return 0;
	}

	//Check Data4 array for equality.
	for (int i = 0; i < 8; i++) {
		if (a->Data4[i] != b->Data4[i]) {
			return 0;
		}
	}

	return 1;
}

int select_guid_from_list(EFI_GUID *guid, EFI_GUID *guid_list[], int len)
{
	int i = 0;
	for (; i < len; i++) {
		if (guid_equal(guid, guid_list[i])) {
			break;
		}
	}
	// It's unlikely fuzzing can reliably come up with a correct guid, given how
	// much entropy there is.  If we're in fuzzing mode, and if we haven't found
	// a match, try to force a match so we get some coverage.  Note, we still
	// want coverage of the section failed to convert code, so treat index ==
	// size as section failed to convert.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (i == len) {
		i = guid->Data1 % (len + 1);
	}
#endif

	return i;
}

void add_untrusted_string(json_object *ir, const char *field_name,
			  const char *str, int len)
{
	int fru_text_len = 0;
	for (; fru_text_len < len; fru_text_len++) {
		char c = str[fru_text_len];
		if (c == '\0') {
			break;
		}
		if (!isprint(c)) {
			fru_text_len = -1;
			break;
		}
	}
	if (fru_text_len >= 0) {
		json_object_object_add(
			ir, field_name,
			json_object_new_string_len(str, fru_text_len));
	}
}

void add_guid(json_object *ir, const char *field_name, EFI_GUID *guid)
{
	char platform_string[GUID_STRING_LENGTH + 1];
	if (!guid_to_string(platform_string, sizeof(platform_string), guid)) {
		return;
	}
	json_object_object_add(
		ir, field_name,
		json_object_new_string_len(platform_string,
					   sizeof(platform_string) - 1));
}

void add_int(json_object *register_ir, const char *field_name, int value)
{
	json_object_object_add(register_ir, field_name,
			       json_object_new_uint64(value));
}

static void add_int_hex_common(json_object *register_ir, const char *field_name,
			       UINT64 value, int len)
{
	char hexstring_buf[EFI_UINT64_HEX_STRING_LEN];
	snprintf(hexstring_buf, EFI_UINT64_HEX_STRING_LEN, "0x%0*llX", len,
		 value);
	json_object_object_add(register_ir, field_name,
			       json_object_new_string(hexstring_buf));
}

void add_int_hex_8(json_object *register_ir, const char *field_name,
		   UINT8 value)
{
	add_int_hex_common(register_ir, field_name, value, 2);
}

void add_int_hex_16(json_object *register_ir, const char *field_name,
		    UINT16 value)
{
	add_int_hex_common(register_ir, field_name, value, 4);
}

void add_int_hex_24(json_object *register_ir, const char *field_name,
		    UINT64 value)
{
	add_int_hex_common(register_ir, field_name, value, 6);
}

void add_int_hex_64(json_object *register_ir, const char *field_name,
		    UINT64 value)
{
	add_int_hex_common(register_ir, field_name, value, 8);
}

void add_bool(json_object *register_ir, const char *field_name, UINT64 value)
{
	json_object_object_add(register_ir, field_name,
			       json_object_new_boolean(value));
}

void add_bool_enum(json_object *register_ir, const char *field_name,
		   const char *value_dict[2], UINT64 value_int)
{
	const char *value = value_dict[0];
	if (value_int > 0) {
		value = value_dict[1];
	}
	json_object_object_add(register_ir, field_name,
			       json_object_new_string(value));
}

void add_dict(json_object *register_ir, const char *field_name, UINT64 value,
	      const char *dict[], size_t dict_size)
{
	json_object *field_ir = json_object_new_object();
	json_object_object_add(register_ir, field_name, field_ir);
	json_object_object_add(field_ir, "raw", json_object_new_uint64(value));

	if (dict != NULL) {
		if (value < dict_size) {
			const char *name = dict[value];
			if (name != NULL) {
				const char *value_name = name;

				json_object_object_add(
					field_ir, "value",
					json_object_new_string(value_name));
			}
		}
	}
}
