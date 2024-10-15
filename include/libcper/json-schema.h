#ifndef CPER_JSON_SCHEMA_H
#define CPER_JSON_SCHEMA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <json.h>

#define JSON_SCHEMA_VERSION    "https://json-schema.org/draft/2020-12/schema"
#define JSON_ERROR_MSG_MAX_LEN 512

int validate_schema(json_object *schema, char *schema_directory,
		    json_object *object, char *error_message);
int validate_schema_from_file(const char *schema_file, json_object *object,
			      char *error_message);
void validate_schema_debug_enable();
void validate_schema_debug_disable();

#ifdef __cplusplus
}
#endif

#endif
