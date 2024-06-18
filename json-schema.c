/**
 * A very basic, non-complete implementation of a validator for the JSON Schema specification,
 * for validating CPER-JSON.
 * 
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <json.h>
#include "json-schema.h"
#include "edk/BaseTypes.h"
#include <linux/limits.h>

//Field definitions.
int json_validator_debug = 0;

//Private pre-definitions.
int validate_field(const char *name, json_object *schema, json_object *object,
		   char *error_message);
int validate_integer(const char *field_name, json_object *schema,
		     json_object *object, char *error_message);
int validate_string(const char *field_name, json_object *schema,
		    json_object *object, const char *error_message);
int validate_object(const char *field_name, json_object *schema,
		    json_object *object, char *error_message);
int validate_array(const char *field_name, json_object *schema,
		   json_object *object, char *error_message);
void log_validator_error(char *error_message, const char *format, ...);
void log_validator_debug(const char *format, ...);
void log_validator_msg(const char *format, va_list args);

//Validates a single JSON object against a provided schema file, returning 1 on success and 0 on failure to validate.
//Error message space must be allocated prior to call.
int validate_schema_from_file(const char *schema_file, json_object *object,
			      char *error_message)
{
	//Load schema IR from file.
	json_object *schema_ir = json_object_from_file(schema_file);
	if (schema_ir == NULL) {
		log_validator_error(error_message,
				    "Failed to load schema from file '%s'.",
				    schema_file);
		return 0;
	}

	//Get the directory of the file.
	char *schema_file_copy = malloc(strlen(schema_file) + 1);
	strcpy(schema_file_copy, schema_file);
	char *schema_dir = dirname(schema_file_copy);

	int result =
		validate_schema(schema_ir, schema_dir, object, error_message);

	//Free memory from directory call.
	free(schema_file_copy);
	json_object_put(schema_ir);

	return result;
}

//Validates a single JSON object against a provided schema, returning 1 on success and 0 on failure to validate.
//Error message space must be allocated prior to call.
//If the schema does not include any other sub-schemas using "$ref", then leaving schema_directory as NULL is valid.
int validate_schema(json_object *schema, char *schema_directory,
		    json_object *object, char *error_message)
{
	//Check that the schema version is the same as this validator.
	json_object *schema_ver = json_object_object_get(schema, "$schema");
	if (schema_ver == NULL || strcmp(json_object_get_string(schema_ver),
					 JSON_SCHEMA_VERSION) != 0) {
		log_validator_error(
			error_message,
			"Provided schema is not of the same version that is referenced by this validator, or is not a schema.");
		return 0;
	}

	//Change current directory into the schema directory.
	char *original_cwd = malloc(PATH_MAX);
	if (getcwd(original_cwd, PATH_MAX) == NULL) {
		log_validator_error(error_message,
				    "Failed fetching the current directory.");
		if (original_cwd) {
			free(original_cwd);
		}
		return 0;
	}
	if (chdir(schema_directory)) {
		log_validator_error(error_message,
				    "Failed to chdir into schema directory.");
		if (original_cwd) {
			free(original_cwd);
		}
		return 0;
	}

	//Parse the top level structure appropriately.
	int result = validate_field("parent", schema, object, error_message);

	//Change back to original CWD.
	if (chdir(original_cwd)) {
		log_validator_error(error_message,
				    "Failed to chdir into original directory.");
	}

	free(original_cwd);

	if (result) {
		log_validator_debug(
			"Successfully validated the provided object against schema.");
	}
	return result;
}

//Validates a single JSON field given a schema/object.
//Returns -1 on fatal/error failure, 0 on validation failure, and 1 on validation.
int validate_field(const char *field_name, json_object *schema,
		   json_object *object, char *error_message)
{
	log_validator_debug("Validating field '%s'...", field_name);

	//If there is a "$ref" field, attempt to load the referenced schema.
	json_object *ref_schema = json_object_object_get(schema, "$ref");
	if (ref_schema != NULL &&
	    json_object_get_type(ref_schema) == json_type_string) {
		log_validator_debug("$ref schema detected for field '%s'.",
				    field_name);

		//Attempt to load. If loading fails, report error.
		const char *ref_path = json_object_get_string(ref_schema);
		json_object *tmp = json_object_from_file(ref_path);
		if (tmp == NULL) {
			log_validator_error(
				error_message,
				"Failed to open referenced schema file '%s'.",
				ref_path);
			return -1;
		}
		json_object_put(tmp);

		log_validator_debug("loaded schema path '%s' for field '%s'.",
				    ref_path, field_name);
	}

	//Get the schema field type.
	json_object *desired_field_type =
		json_object_object_get(schema, "type");
	if (desired_field_type == NULL ||
	    !json_object_is_type(desired_field_type, json_type_string)) {
		log_validator_error(
			error_message,
			"Desired field type not provided within schema/is not a string for field '%s' (schema violation).",
			field_name);
		return -1;
	}

	//Check the field types are actually equal.
	const char *desired_field_type_str =
		json_object_get_string(desired_field_type);
	if (!((!strcmp(desired_field_type_str, "object") &&
	       json_object_is_type(object, json_type_object)) ||
	      (!strcmp(desired_field_type_str, "array") &&
	       json_object_is_type(object, json_type_array)) ||
	      (!strcmp(desired_field_type_str, "integer") &&
	       json_object_is_type(object, json_type_int)) ||
	      (!strcmp(desired_field_type_str, "string") &&
	       json_object_is_type(object, json_type_string)) ||
	      (!strcmp(desired_field_type_str, "boolean") &&
	       json_object_is_type(object, json_type_boolean)) ||
	      (!strcmp(desired_field_type_str, "double") &&
	       json_object_is_type(object, json_type_double)))) {
		log_validator_error(error_message,
				    "Field type match failed for field '%s'.",
				    field_name);
		return 0;
	}

	//If the schema contains a "oneOf" array, we need to validate the field against each of the
	//possible options in turn.
	json_object *one_of = json_object_object_get(schema, "oneOf");
	if (one_of != NULL && json_object_get_type(one_of) == json_type_array) {
		log_validator_debug("oneOf options detected for field '%s'.",
				    field_name);

		int len = json_object_array_length(one_of);
		int validated = 0;
		for (int i = 0; i < len; i++) {
			//If the "oneOf" member isn't an object, warn on schema violation.
			json_object *one_of_option =
				json_object_array_get_idx(one_of, i);
			if (one_of_option == NULL ||
			    json_object_get_type(one_of_option) !=
				    json_type_object) {
				log_validator_debug(
					"Schema Warning: 'oneOf' member for field '%s' is not an object, schema violation.",
					field_name);
				continue;
			}

			//Validate field with schema.
			validated = validate_field(field_name, one_of_option,
						   object, error_message);
			if (validated == -1) {
				return -1;
			}
			if (validated) {
				break;
			}
		}

		//Return if failed all checks.
		if (!validated) {
			log_validator_error(
				error_message,
				"No schema object structures matched provided object for field '%s'.",
				field_name);
			return 0;
		}
	}

	//Switch and validate each type in turn.
	switch (json_object_get_type(object)) {
	case json_type_int:
		return validate_integer(field_name, schema, object,
					error_message);
	case json_type_string:
		return validate_string(field_name, schema, object,
				       error_message);
	case json_type_object:
		return validate_object(field_name, schema, object,
				       error_message);
	case json_type_array:
		return validate_array(field_name, schema, object,
				      error_message);

	//We don't perform extra validation on this type.
	default:
		log_validator_debug(
			"validation passed for '%s' (no extra validation).",
			field_name);
		return 1;
	}
}

//Validates a single integer value according to the given specification.
int validate_integer(const char *field_name, json_object *schema,
		     json_object *object, char *error_message)
{
	//Is there a minimum/maximum specified? If so, check those.
	//Validate minimum.
	json_object *min_value = json_object_object_get(schema, "minimum");
	if (min_value != NULL &&
	    json_object_is_type(min_value, json_type_int)) {
		int min_value_int = json_object_get_int(min_value);
		if (json_object_get_uint64(object) < (uint64_t)min_value_int) {
			log_validator_error(
				error_message,
				"Failed to validate integer field '%s'. Value was below minimum of %d.",
				field_name, min_value_int);
			return 0;
		}
	}

	//Validate maximum.
	json_object *max_value = json_object_object_get(schema, "maximum");
	if (max_value != NULL &&
	    json_object_is_type(max_value, json_type_int)) {
		int max_value_int = json_object_get_int(max_value);
		if (json_object_get_uint64(object) > (uint64_t)max_value_int) {
			log_validator_error(
				error_message,
				"Failed to validate integer field '%s'. Value was above maximum of %d.",
				field_name, max_value_int);
			return 0;
		}
	}

	return 1;
}

//Validates a single string value according to the given specification.
int validate_string(const char *field_name, json_object *schema,
		    json_object *object, const char *error_message)
{
	//todo: if there is a "pattern" field, verify the string with RegEx.
	(void)field_name;
	(void)schema;
	(void)object;
	(void)error_message;

	return 1;
}

//Validates a single object value according to the given specification.
int validate_object(const char *field_name, json_object *schema,
		    json_object *object, char *error_message)
{
	//Are there a set of "required" fields? If so, check they all exist.
	json_object *required_fields =
		json_object_object_get(schema, "required");
	if (required_fields != NULL &&
	    json_object_get_type(required_fields) == json_type_array) {
		log_validator_debug(
			"Required fields found for '%s', matching...",
			field_name);

		int len = json_object_array_length(required_fields);
		for (int i = 0; i < len; i++) {
			//Get the required field from schema.
			json_object *required_field =
				json_object_array_get_idx(required_fields, i);
			if (json_object_get_type(required_field) !=
			    json_type_string) {
				log_validator_error(
					error_message,
					"Required field for object '%s' is not a string (schema violation).",
					field_name);
				return 0;
			}

			//Does it exist in the object?
			const char *required_field_str =
				json_object_get_string(required_field);
			if (json_object_object_get(
				    object, required_field_str) == NULL) {
				log_validator_error(
					error_message,
					"Required field '%s' was not present in object '%s'.",
					required_field_str, field_name);
				return 0;
			}
		}
	}

	//Get additional properties value in advance.
	json_object *additional_properties =
		json_object_object_get(schema, "additionalProperties");
	int additional_properties_allowed = 0;
	if (additional_properties != NULL &&
	    json_object_get_type(additional_properties) == json_type_boolean) {
		additional_properties_allowed =
			json_object_get_boolean(additional_properties);
	}

	//Run through the "properties" object and validate each of those in turn.
	json_object *properties = json_object_object_get(schema, "properties");
	if (properties != NULL &&
	    json_object_get_type(properties) == json_type_object) {
		json_object_object_foreach(properties, key, value)
		{
			//If the given property name does not exist on the target object, ignore and continue next.
			json_object *object_prop =
				json_object_object_get(object, key);
			if (object_prop == NULL) {
				continue;
			}

			//Validate against the schema.
			if (!validate_field(key, value, object_prop,
					    error_message)) {
				return 0;
			}
		}

		//If additional properties are banned, validate that no additional properties exist.
		if (!additional_properties_allowed) {
			json_object_object_foreach(object, key, value)
			{
				//Avoid compiler warning
				(void)value;

				//If the given property name does not exist on the schema object, fail validation.
				const json_object *schema_prop =
					json_object_object_get(properties, key);
				if (schema_prop == NULL) {
					log_validator_error(
						error_message,
						"Invalid additional property '%s' detected on field '%s'.",
						key, field_name);
					return 0;
				}
			}
		}
	}

	return 1;
}

//Validates a single array value according to the given specification.
int validate_array(const char *field_name, json_object *schema,
		   json_object *object, char *error_message)
{
	//Iterate all items in the array, and validate according to the "items" schema.
	json_object *items_schema = json_object_object_get(schema, "items");
	if (items_schema != NULL &&
	    json_object_get_type(items_schema) == json_type_object) {
		int array_len = json_object_array_length(object);
		for (int i = 0; i < array_len; i++) {
			if (!validate_field(field_name, items_schema,
					    json_object_array_get_idx(object,
								      i),
					    error_message)) {
				return 0;
			}
		}
	}

	return 1;
}

//Enables/disables debugging globally for the JSON validator.
void validate_schema_debug_enable()
{
	json_validator_debug = 1;
}
void validate_schema_debug_disable()
{
	json_validator_debug = 0;
}

//Logs an error message to the given error message location and (optionally) provides debug output.
void log_validator_error(char *error_message, const char *format, ...)
{
	va_list args;

	//Log error to error out.
	va_start(args, format);
	vsnprintf(error_message, JSON_ERROR_MSG_MAX_LEN, format, args);
	va_end(args);

	//Debug message if necessary.
	va_start(args, format);
	log_validator_msg(format, args);
	va_end(args);
}

//Logs a debug message to stdout, if validator debug is enabled.
void log_validator_debug(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_validator_msg(format, args);
	va_end(args);
}

//Logs a single validator debug/error message.
void log_validator_msg(const char *format, va_list args)
{
	//Print debug output if debug is on.
	if (json_validator_debug) {
		//Make new format string for error.
		const char *header = "json_validator: ";
		char *new_format = malloc(strlen(header) + strlen(format) + 2);
		strcpy(new_format, header);
		strcat(new_format, format);
		strcat(new_format, "\n");

		//Print & free format.
		vfprintf(stdout, new_format, args);
		free(new_format);
	}
}
