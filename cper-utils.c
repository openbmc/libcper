/**
 * Describes utility functions for parsing CPER into JSON IR.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <json.h>
#include "edk/Cper.h"
#include "cper-utils.h"

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
		json_object_object_add(result, names[i],
				       json_object_new_uint64(*cur));
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
void timestamp_to_string(char *out, EFI_ERROR_TIME_STAMP *timestamp)
{
	sprintf(out, "%02hhu%02hhu-%02hhu-%02hhuT%02hhu:%02hhu:%02hhu.000",
		bcd_to_int(timestamp->Century) %
			100,			   //Cannot go to three digits.
		bcd_to_int(timestamp->Year) % 100, //Cannot go to three digits.
		bcd_to_int(timestamp->Month), bcd_to_int(timestamp->Day),
		bcd_to_int(timestamp->Hours), bcd_to_int(timestamp->Minutes),
		bcd_to_int(timestamp->Seconds));
}

//Converts a single timestamp string to an EFI timestamp.
void string_to_timestamp(EFI_ERROR_TIME_STAMP *out, const char *timestamp)
{
	//Ignore invalid timestamps.
	if (timestamp == NULL) {
		return;
	}

	sscanf(timestamp, "%2hhu%2hhu-%hhu-%hhuT%hhu:%hhu:%hhu.000",
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
void guid_to_string(char *out, EFI_GUID *guid)
{
	sprintf(out, "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
		guid->Data1, guid->Data2, guid->Data3, guid->Data4[0],
		guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4],
		guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

//Helper function to convert a string into an EDK EFI GUID.
void string_to_guid(EFI_GUID *out, const char *guid)
{
	//Ignore invalid GUIDs.
	if (guid == NULL) {
		return;
	}

	sscanf(guid,
	       "%08x-%04hx-%04hx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
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
