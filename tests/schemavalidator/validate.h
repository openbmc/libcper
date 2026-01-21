#ifndef __SCHEMAVALIDATOR_H
#define __SCHEMAVALIDATOR_H

#include <json-c/json.h>

int _schemavalidator_load(const char *jsonfile, const char *jsonschema);
int __schemavalidator_inspect_type(json_object *jobj, const char *type,
				   json_object *joutput_node);
int _schemavalidator_check_type(json_object *jobj, json_object *jschema,
				json_object *joutput_node);
int _schemavalidator_check_required(json_object *jobj, json_object *jschema,
				    json_object *joutput_node);
int _schemavalidator_check_properties(json_object *jobj, json_object *jschema,
				      json_object *joutput_node);
int _schemavalidator_check_prefixItems_and_items(json_object *jobj,
						 json_object *jschema,
						 json_object *joutput_node);
int _schemavalidator_value_is_equal(json_object *jobj1, json_object *jobj2);
int _schemavalidator_check_const(json_object *jobj, json_object *jschema,
				 json_object *joutput_node);
int _schemavalidator_check_enums(json_object *jobj, json_object *jschema,
				 json_object *joutput_node);
int _schemavalidator_check_uniqueItems(json_object *jobj, json_object *jschema,
				       json_object *joutput_node);
int _schemavalidator_check_maxmin_items(json_object *jobj, json_object *jschema,
					json_object *joutput_node);
int _schemavalidator_validate_array(json_object *jobj, json_object *jschema,
				    json_object *joutput_node);
int _schemavalidator_validate_object(json_object *jobj, json_object *jschema,
				     json_object *joutput_node);
int _schemavalidator_validate_string(json_object *jobj, json_object *jschema,
				     json_object *joutput_node);
int _schemavalidator_validate_integer(json_object *jobj, json_object *jschema,
				      json_object *joutput_node);
int _schemavalidator_validate_double(json_object *jobj, json_object *jschema,
				     json_object *joutput_node);
int _schemavalidator_validate_number(json_object *jobj, json_object *jschema,
				     double value, json_object *joutput_node);
int _schemavalidator_validate_boolean(json_object *jobj, json_object *jschema,
				      json_object *joutput_node);
int _schemavalidator_validate_instance(json_object *jobj, json_object *jschema,
				       json_object *joutput_node);

json_object *_schemavalidator_output_create_node(const char *name);
void _schemavalidator_output_append_node(json_object *joutput,
					 json_object *jnode);
json_object *
_schemavalidator_output_create_and_append_node(json_object *joutput,
					       const char *name);
json_object *_schemavalidator_output_create_and_append_node_concatnames(
	json_object *joutput, char *name1, char *name2);

enum schemavalidator_errors {
	SCHEMAVALIDATOR_ERR_VALID = 0,
	SCHEMAVALIDATOR_ERR_GENERAL_ERROR,
	SCHEMAVALIDATOR_ERR_JSON_NOT_FOUND,
	SCHEMAVALIDATOR_ERR_SCHEMA_NOT_FOUND,
	SCHEMAVALIDATOR_ERR_WRONG_ARGS,
	SCHEMAVALIDATOR_ERR_SCHEMA_ERROR,
	SCHEMAVALIDATOR_ERR_INVALID,
	SCHEMAVALIDATOR_REGEX_MISMATCH,
	SCHEMAVALIDATOR_REGEX_MATCH,
	SCHEMAVALIDATOR_REGEX_COMPILE_FAILED,
	SCHEMAVALIDATOR_ERR_MAX
};

void _schemavalidator_output_apply_result(json_object *joutput,
					  enum schemavalidator_errors err);
void _schemavalidator_output_print_errors(json_object *joutput);

int schemavalidator_validate(json_object *jobj, json_object *jschema);

const char *schemavalidator_errorstr(unsigned int schemavalidator_errors);

#endif //__SCHEMAVALIDATOR_H
