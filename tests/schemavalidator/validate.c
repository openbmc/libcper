#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <json-c/json.h>

#include "validate.h"

json_object *json = NULL;
json_object *schema = NULL;
json_object *defs = NULL;

static char *schemavalidator_errstr[SCHEMAVALIDATOR_ERR_MAX] = {
	"VALID",
	"GENERAL ERROR",
	"JSON FILE NOT FOUND",
	"SCHEMA FILE NOT FOUND",
	"WRONG ARGUEMNTS GIVEN",
	"SCHEMA ERROR",
	"INVALID",
	"REGEX MISMATCH",
	"REGEX MATCH",
	"REGEX COMPILE FAILED"
};

const char *schemavalidator_errorstr(unsigned int schemavalidator_errors)
{
	if (schemavalidator_errors < SCHEMAVALIDATOR_ERR_MAX) {
		return schemavalidator_errstr[schemavalidator_errors];
	}
	return NULL;
}

int _schemavalidator_load(const char *jsonfile, const char *jsonschema)
{
	json = json_object_from_file(jsonfile);
	if (json == NULL) {
		return SCHEMAVALIDATOR_ERR_JSON_NOT_FOUND;
	}

	schema = json_object_from_file(jsonschema);
	if (schema == NULL) {
		json_object_put(json);
		return SCHEMAVALIDATOR_ERR_SCHEMA_NOT_FOUND;
	}

	return SCHEMAVALIDATOR_ERR_VALID;
}

int __schemavalidator_inspect_type(json_object *jobj, const char *type,
				   json_object *joutput_node)
{
	if (strcmp(type, "object") == 0) {
		if (json_object_is_type(jobj, json_type_object)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "array") == 0) {
		if (json_object_is_type(jobj, json_type_array)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "string") == 0) {
		if (json_object_is_type(jobj, json_type_string)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "integer") == 0) {
		if (json_object_is_type(jobj, json_type_int)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
		if (json_object_is_type(jobj, json_type_double)) {
			double value = json_object_get_double(jobj);
			if (value ==
			    round(value)) { // "zero fractional part is an integer"
				return SCHEMAVALIDATOR_ERR_VALID;
			}
		}
	} else if (strcmp(type, "double") == 0) {
		if (json_object_is_type(jobj, json_type_double)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "number") == 0) {
		if (json_object_is_type(jobj, json_type_double) ||
		    json_object_is_type(jobj, json_type_int)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "boolean") == 0) {
		if (json_object_is_type(jobj, json_type_boolean)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else if (strcmp(type, "null") == 0) {
		if (json_object_is_type(jobj, json_type_null)) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	} else {
		printf("WARN unknown type in check type %s\n", type);
		json_object *jnode =
			_schemavalidator_output_create_and_append_node(
				joutput_node, "type");
		_schemavalidator_output_apply_result(
			jnode, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
		return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
	}
	json_object *jnode = _schemavalidator_output_create_and_append_node(
		joutput_node, "type");
	_schemavalidator_output_apply_result(jnode,
					     SCHEMAVALIDATOR_ERR_INVALID);

	return SCHEMAVALIDATOR_ERR_INVALID;
}

int schemavalidator_check_bool(json_object *jobj, json_object *jschema,
			       json_object *joutput_node)
{
	(void)jobj;
	// check if jschema is a bool, true or false
	int err;
	if (json_object_is_type(jschema, json_type_boolean)) {
		json_object *jnode =
			_schemavalidator_output_create_and_append_node(
				joutput_node, "bool");
		json_bool value = json_object_get_boolean(jschema);
		err = value == 0 ? SCHEMAVALIDATOR_ERR_INVALID :
				   SCHEMAVALIDATOR_ERR_VALID;
		_schemavalidator_output_apply_result(jnode, err);
		return err;
	}
	return SCHEMAVALIDATOR_ERR_VALID;
}

int _schemavalidator_check_type(json_object *jobj, json_object *jschema,
				json_object *joutput_node)
{
	json_object *jnode;
	json_object *jtype = json_object_object_get(jschema, "type");
	if (jtype == NULL) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}
	if (json_object_is_type(jtype, json_type_string)) {
		const char *type = json_object_get_string(jtype);
		return __schemavalidator_inspect_type(jobj, type, joutput_node);
	}
	if (json_object_is_type(jtype, json_type_array)) {
		int arraylen = json_object_array_length(jtype);
		for (int i = 0; i < arraylen; i++) {
			json_object *iobj = json_object_array_get_idx(jtype, i);
			if (!json_object_is_type(iobj, json_type_string)) {
				goto check_type_schema_error;
			}
			const char *type = json_object_get_string(iobj);
			int err = __schemavalidator_inspect_type(jobj, type,
								 joutput_node);
			if (err == SCHEMAVALIDATOR_ERR_VALID) {
				return SCHEMAVALIDATOR_ERR_VALID;
			}
		}
		jnode = _schemavalidator_output_create_and_append_node(
			joutput_node, "type");
		_schemavalidator_output_apply_result(
			jnode, SCHEMAVALIDATOR_ERR_INVALID);
		return SCHEMAVALIDATOR_ERR_INVALID;
	}
check_type_schema_error:
	jnode = _schemavalidator_output_create_and_append_node(joutput_node,
							       "type");
	_schemavalidator_output_apply_result(jnode,
					     SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
	return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
}

int _schemavalidator_check_required(json_object *jobj, json_object *jschema,
				    json_object *joutput_node)
{
	//printf("%s\n%s\n", __func__, json_object_to_json_string(jobj));
	json_object *jarray = json_object_object_get(jschema, "required");
	if (!jarray) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	json_object *jrequired_node =
		_schemavalidator_output_create_and_append_node(joutput_node,
							       "required");
	int missing_required_key = 0;

	int arraylen = json_object_array_length(jarray);
	for (int i = 0; i < arraylen; i++) {
		json_object *iobj = json_object_array_get_idx(jarray, i);
		const char *key = json_object_get_string(iobj);
		if (key) {
			//printf("%s\n", key);
			// use json_object_object_get_ex becuase of json_type_null types
			json_object *required_object = NULL;
			int err = json_object_object_get_ex(jobj, key,
							    &required_object);
			if (err == 0) {
				// printf("required key missing: %s\n", key);
				json_object *jkeynode =
					_schemavalidator_output_create_and_append_node(
						jrequired_node, key);
				_schemavalidator_output_apply_result(
					jkeynode, SCHEMAVALIDATOR_ERR_INVALID);
				missing_required_key = 1;
			}
		}
	}
	int ret = missing_required_key == 1 ? SCHEMAVALIDATOR_ERR_INVALID :
					      SCHEMAVALIDATOR_ERR_VALID;
	_schemavalidator_output_apply_result(jrequired_node, ret);
	return ret;
}

int _schemavalidator_check_properties(json_object *jobj, json_object *jschema,
				      json_object *joutput_node)
{
	// printf("%s\n", __func__);

	json_object *jprops = json_object_object_get(jschema, "properties");
	if (!jprops) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	json_object *jproperties_node =
		_schemavalidator_output_create_and_append_node(joutput_node,
							       "properties");
	int properties_valid = 1;
	json_object_object_foreach(jprops, jprop_key, jprop_val)
	{
		// printf("key of prop is %s\n", jprop_key);
		json_object *iobj = json_object_object_get(jobj, jprop_key);
		//printf("iobj %s type %d\nkey %s\nval %s\n", json_object_get_string(iobj), json_object_get_type(iobj), jprop_key, json_object_get_string(jprop_val));
		if (iobj) {
			json_object *jprop_item_tmp_node =
				_schemavalidator_output_create_node(jprop_key);
			int err = _schemavalidator_validate_instance(
				iobj, jprop_val, jprop_item_tmp_node);
			if (err != SCHEMAVALIDATOR_ERR_VALID) {
				properties_valid = 0;
				_schemavalidator_output_apply_result(
					jprop_item_tmp_node, err);
				_schemavalidator_output_append_node(
					jproperties_node, jprop_item_tmp_node);
			} else {
				json_object_put(jprop_item_tmp_node);
			}
		}
	}
	int ret = properties_valid == 1 ? SCHEMAVALIDATOR_ERR_VALID :
					  SCHEMAVALIDATOR_ERR_INVALID;
	_schemavalidator_output_apply_result(jproperties_node, ret);
	return ret;
}

int _schemavalidator_check_prefixItems_and_items(json_object *jobj,
						 json_object *jschema,
						 json_object *joutput_node)
{
	json_object *jprefixitems =
		json_object_object_get(jschema, "prefixItems");
	json_object *jitems = json_object_object_get(jschema, "items");

	int prefixitems_ok = 1;
	int items_ok = 1;

	if (jprefixitems) {
		json_object *jprefixitems_node =
			_schemavalidator_output_create_and_append_node(
				joutput_node, "prefixItems");

		if (!json_object_is_type(jprefixitems, json_type_array)) {
			_schemavalidator_output_apply_result(
				jprefixitems_node,
				SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
			return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
		}

		int jobj_arraylen = json_object_array_length(jobj);
		int prefixitems_arraylen =
			json_object_array_length(jprefixitems);
		for (int i = 0; i < jobj_arraylen && i < prefixitems_arraylen;
		     i++) {
			//printf("i=%d prefixitems\n", i);
			json_object *iobj = json_object_array_get_idx(jobj, i);
			json_object *ischema =
				json_object_array_get_idx(jprefixitems, i);

			char numstr[12];
			snprintf(numstr, sizeof(numstr), "%d", i);
			json_object *jarrayitem_tmp_node =
				_schemavalidator_output_create_node(numstr);

			int err = _schemavalidator_validate_instance(
				iobj, ischema, jarrayitem_tmp_node);
			if (err) {
				_schemavalidator_output_apply_result(
					jprefixitems_node, err);
				_schemavalidator_output_append_node(
					jprefixitems_node, jarrayitem_tmp_node);
				prefixitems_ok = 0;
			} else {
				json_object_put(jarrayitem_tmp_node);
			}
		}
		int prefixitems_ret = (prefixitems_ok == 1) ?
					      SCHEMAVALIDATOR_ERR_VALID :
					      SCHEMAVALIDATOR_ERR_INVALID;
		_schemavalidator_output_apply_result(jprefixitems_node,
						     prefixitems_ret);
	}

	if (jitems) {
		json_object *jitems_node =
			_schemavalidator_output_create_and_append_node(
				joutput_node, "items");

		if (!json_object_is_type(jitems, json_type_object) &&
		    !json_object_is_type(jitems, json_type_boolean)) {
			_schemavalidator_output_apply_result(
				jitems_node, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
			return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
		}

		int jobj_arraylen = json_object_array_length(jobj);
		int items_arraylen = 0;
		for (int i = items_arraylen; i < jobj_arraylen; i++) {
			//printf("i=%d items\n", i);
			json_object *iobj = json_object_array_get_idx(jobj, i);
			char numstr[12];
			snprintf(numstr, sizeof(numstr), "%d", i);
			json_object *jarrayitem_tmp_node =
				_schemavalidator_output_create_node(numstr);
			int err = _schemavalidator_validate_instance(
				iobj, jitems, jarrayitem_tmp_node);
			if (err) {
				_schemavalidator_output_apply_result(
					jarrayitem_tmp_node, err);
				_schemavalidator_output_append_node(
					jitems_node, jarrayitem_tmp_node);
				items_ok = 0;
			} else {
				json_object_put(jarrayitem_tmp_node);
			}
		}
		int items_ret = (items_ok == 1) ? SCHEMAVALIDATOR_ERR_VALID :
						  SCHEMAVALIDATOR_ERR_INVALID;
		_schemavalidator_output_apply_result(jitems_node, items_ret);
	}
	int ret = (prefixitems_ok == 1 && items_ok == 1) ?
			  SCHEMAVALIDATOR_ERR_VALID :
			  SCHEMAVALIDATOR_ERR_INVALID;
	return ret;
}

int _schemavalidator_value_is_equal(json_object *jobj1, json_object *jobj2)
{
	if (json_object_equal(jobj1, jobj2)) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	if (json_object_is_type(jobj1, json_type_double) &&
	    json_object_is_type(jobj2, json_type_int)) {
		double value = json_object_get_double(jobj1);
		double value2 = json_object_get_int64(jobj2);
		if (value == round(value) && value == value2) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	}

	if (json_object_is_type(jobj1, json_type_int) &&
	    json_object_is_type(jobj2, json_type_double)) {
		double value = json_object_get_double(jobj2);
		double value2 = json_object_get_int64(jobj1);
		if (value == round(value) && value == value2) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	}

	return SCHEMAVALIDATOR_ERR_INVALID;
}

int _schemavalidator_check_const(json_object *jobj, json_object *jschema,
				 json_object *joutput_node)
{
	json_object *jconst;
	int err = json_object_object_get_ex(jschema, "const", &jconst);
	if (err == 0) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	err = _schemavalidator_value_is_equal(jobj, jconst);
	if (err == SCHEMAVALIDATOR_ERR_VALID) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	json_object *jnode = _schemavalidator_output_create_and_append_node(
		joutput_node, "const");
	_schemavalidator_output_apply_result(jnode,
					     SCHEMAVALIDATOR_ERR_INVALID);
	return SCHEMAVALIDATOR_ERR_INVALID;
}

int _schemavalidator_check_enums(json_object *jobj, json_object *jschema,
				 json_object *joutput_node)
{
	json_object *jenum_array = json_object_object_get(jschema, "enum");

	if (!jenum_array) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	if (!json_object_is_type(jenum_array, json_type_array)) {
		json_object *jnode =
			_schemavalidator_output_create_and_append_node(
				joutput_node, "enum");
		_schemavalidator_output_apply_result(
			jnode, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
		return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
	}

	int arraylen = json_object_array_length(jenum_array);
	for (int i = 0; i < arraylen; i++) {
		json_object *ienum = json_object_array_get_idx(jenum_array, i);
		int err = _schemavalidator_value_is_equal(jobj, ienum);
		if (err == SCHEMAVALIDATOR_ERR_VALID) {
			return SCHEMAVALIDATOR_ERR_VALID;
		}
	}
	// printf("ERROR: enum check failed (%s not in enum)\n", json_object_to_json_string(jobj));

	json_object *jnode = _schemavalidator_output_create_and_append_node(
		joutput_node, "enum");
	_schemavalidator_output_apply_result(jnode,
					     SCHEMAVALIDATOR_ERR_INVALID);
	return SCHEMAVALIDATOR_ERR_INVALID;
}

int _schemavalidator_check_uniqueItems(json_object *jobj, json_object *jschema,
				       json_object *joutput_node)
{
	json_object *juniq = json_object_object_get(jschema, "uniqueItems");
	if (!juniq) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	json_object *juniqueitems_node =
		_schemavalidator_output_create_and_append_node(joutput_node,
							       "uniqueItems");

	if (!json_object_is_type(juniq, json_type_boolean)) {
		_schemavalidator_output_apply_result(
			juniqueitems_node, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
		return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
	}

	// uniqueItems=false is valid
	if (json_object_get_boolean(juniq) == 0) {
		_schemavalidator_output_apply_result(juniqueitems_node,
						     SCHEMAVALIDATOR_ERR_VALID);
		return SCHEMAVALIDATOR_ERR_VALID;
	}

	int uniqueitems_ok = 1;
	int arraylen = json_object_array_length(jobj);
	for (int i = 0; i < arraylen - 1; i++) {
		json_object *iobj = json_object_array_get_idx(jobj, i);
		for (int j = i + 1; j < arraylen; j++) {
			json_object *uobj = json_object_array_get_idx(jobj, j);
			if (json_object_equal(iobj, uobj) == 1) {
				uniqueitems_ok = 0;
				char numstr[12];
				snprintf(numstr, sizeof(numstr), "%d", i);
				json_object *jnotunique_node =
					_schemavalidator_output_create_and_append_node(
						juniqueitems_node, numstr);
				_schemavalidator_output_apply_result(
					jnotunique_node,
					SCHEMAVALIDATOR_ERR_INVALID);
			}
		}
	}
	int ret = uniqueitems_ok == 1 ? SCHEMAVALIDATOR_ERR_VALID :
					SCHEMAVALIDATOR_ERR_INVALID;
	_schemavalidator_output_apply_result(juniqueitems_node, ret);
	return ret;
}

int _schemavalidator_check_maxmin_items(json_object *jobj, json_object *jschema,
					json_object *joutput_node)
{
	int err = SCHEMAVALIDATOR_ERR_VALID;
	int arraylen = json_object_array_length(jobj);

	json_object *jmax = json_object_object_get(jschema, "maxItems");
	if (jmax) {
		if (json_object_is_type(jmax, json_type_int) ||
		    json_object_is_type(jmax, json_type_double)) {
			int maxitems = json_object_get_double(jmax);
			if (arraylen > maxitems) {
				json_object *jmaxitems_node =
					_schemavalidator_output_create_and_append_node(
						joutput_node, "maxItems");
				_schemavalidator_output_apply_result(
					jmaxitems_node,
					SCHEMAVALIDATOR_ERR_INVALID);
				err = SCHEMAVALIDATOR_ERR_INVALID;
			}
		}
	}

	json_object *jmin = json_object_object_get(jschema, "minItems");
	if (jmin) {
		if (json_object_is_type(jmin, json_type_int) ||
		    json_object_is_type(jmin, json_type_double)) {
			int minitems = json_object_get_double(jmin);
			if (arraylen < minitems) {
				json_object *jminitems_node =
					_schemavalidator_output_create_and_append_node(
						joutput_node, "minItems");
				_schemavalidator_output_apply_result(
					jminitems_node,
					SCHEMAVALIDATOR_ERR_INVALID);
				err = SCHEMAVALIDATOR_ERR_INVALID;
			}
		}
	}

	// if (err)
	//     printf("ERROR: failed at maxItems or minItems check\n");
	return err;
}

int _schemavalidator_validate_array(json_object *jobj, json_object *jschema,
				    json_object *joutput_node)
{
	int err;

	err = _schemavalidator_check_prefixItems_and_items(jobj, jschema,
							   joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_uniqueItems(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_maxmin_items(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	return SCHEMAVALIDATOR_ERR_VALID;
}

int _schemavalidator_validate_object(json_object *jobj, json_object *jschema,
				     json_object *joutput_node)
{
	int err;
	if (defs == NULL) {
		defs = json_object_object_get(jschema, "$defs");
	}

	err = _schemavalidator_check_required(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_properties(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	return SCHEMAVALIDATOR_ERR_VALID;
}

int utf8_length(const char *str)
{
	const char *pointer = str;
	int len = 0;
	while (pointer[0]) {
		if ((pointer[0] & 0xC0) != 0x80) {
			len++;
		}
		pointer++;
	}
	return len;
}

int _schemavalidator_validate_string(json_object *jobj, json_object *jschema,
				     json_object *joutput_node)
{
	const char *str = json_object_get_string(jobj);
	//printf("strlen of %s %ld %d %d\n", str, strlen(str), json_object_get_string_len(jobj), utf8_length(str));

	int minlength_ok = 1;
	json_object *jminlen = json_object_object_get(jschema, "minLength");
	if (jminlen) {
		int minlen = json_object_get_int64(jminlen);
		if (utf8_length(str) < minlen) {
			minlength_ok = 0;
			json_object *jminlength_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "minLength");
			_schemavalidator_output_apply_result(
				jminlength_node, SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int maxlength_ok = 1;
	json_object *jmaxlen = json_object_object_get(jschema, "maxLength");
	if (jmaxlen) {
		int maxlen = json_object_get_int64(jmaxlen);
		if (utf8_length(str) > maxlen) {
			maxlength_ok = 0;
			json_object *jmaxlength_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "maxLength");
			_schemavalidator_output_apply_result(
				jmaxlength_node, SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int enums_ok = 1;
	int err = _schemavalidator_check_enums(jobj, jschema, joutput_node);
	if (err) {
		if (err == SCHEMAVALIDATOR_ERR_SCHEMA_ERROR) {
			// _schemavalidator_output_apply_result(joutput_node, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
			return err;
		}
		enums_ok = 0;
	}

	int ret = minlength_ok == 1 && maxlength_ok == 1 && enums_ok == 1 ?
			  SCHEMAVALIDATOR_ERR_VALID :
			  SCHEMAVALIDATOR_ERR_INVALID;
	// _schemavalidator_output_apply_result(joutput_node, ret);
	return ret;
}

int _schemavalidator_validate_integer(json_object *jobj, json_object *jschema,
				      json_object *joutput_node)
{
	(void)jobj;
	double value = (double)json_object_get_int64(jobj);
	int err = _schemavalidator_validate_number(jobj, jschema, value,
						   joutput_node);
	return err;
}

int _schemavalidator_validate_double(json_object *jobj, json_object *jschema,
				     json_object *joutput_node)
{
	(void)jobj;
	double value = json_object_get_double(jobj);
	int err = _schemavalidator_validate_number(jobj, jschema, value,
						   joutput_node);
	return err;
}

int _schemavalidator_validate_number(json_object *jobj, json_object *jschema,
				     double value, json_object *joutput_node)
{
	(void)jobj;
	int multipleOf_ok = 1;
	json_object *jmult = json_object_object_get(jschema, "multipleOf");
	if (jmult) {
		double multipland = (double)json_object_get_double(jmult);
		if (multipland == 0.0) {
			json_object *jmultipleOf_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "multipleOf");
			_schemavalidator_output_apply_result(
				jmultipleOf_node,
				SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
			// _schemavalidator_output_apply_result(joutput_node, SCHEMAVALIDATOR_ERR_SCHEMA_ERROR);
			return SCHEMAVALIDATOR_ERR_SCHEMA_ERROR;
		}

		double divided = value / multipland;
		if (isinf(divided) != 0 || divided != round(divided)) {
			multipleOf_ok = 0;
		}
		if (multipleOf_ok == 0) {
			json_object *jmultipleOf_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "multipleOf");
			_schemavalidator_output_apply_result(
				jmultipleOf_node, SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int minimum_ok = 1;
	json_object *jmin = json_object_object_get(jschema, "minimum");
	if (jmin) {
		double min = (double)json_object_get_double(jmin);
		if (value < min) {
			minimum_ok = 0;
			json_object *jminimum_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "minimum");
			_schemavalidator_output_apply_result(
				jminimum_node, SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int exclusiveMinimum_ok = 1;
	json_object *jexclmin =
		json_object_object_get(jschema, "exclusiveMinimum");
	if (jexclmin) {
		double min = (double)json_object_get_double(jexclmin);
		if (value <= min) {
			exclusiveMinimum_ok = 0;
			json_object *jexclusiveMinimum_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "exclusiveMinimum");
			_schemavalidator_output_apply_result(
				jexclusiveMinimum_node,
				SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int maximum_ok = 1;
	json_object *jmax = json_object_object_get(jschema, "maximum");
	if (jmax) {
		double max = (double)json_object_get_double(jmax);
		if (value > max) {
			maximum_ok = 0;
			json_object *jmaximum_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "maximum");
			_schemavalidator_output_apply_result(
				jmaximum_node, SCHEMAVALIDATOR_ERR_INVALID);
		}
	}

	int exclusiveMaximum_ok = 1;
	json_object *jexclmax =
		json_object_object_get(jschema, "exclusiveMaximum");
	if (jexclmax) {
		double max = (double)json_object_get_double(jexclmax);
		if (value >= max) {
			exclusiveMaximum_ok = 0;
			json_object *jexclusiveMaximum_node =
				_schemavalidator_output_create_and_append_node(
					joutput_node, "exclusiveMaximum");
			_schemavalidator_output_apply_result(
				jexclusiveMaximum_node,
				SCHEMAVALIDATOR_ERR_INVALID);
		}
	}
	int ret = multipleOf_ok == 1 && minimum_ok == 1 &&
				  exclusiveMinimum_ok == 1 && maximum_ok == 1 &&
				  exclusiveMaximum_ok == 1 ?
			  SCHEMAVALIDATOR_ERR_VALID :
			  SCHEMAVALIDATOR_ERR_INVALID;
	// _schemavalidator_output_apply_result(joutput_node, ret);
	return ret;
}

int _schemavalidator_validate_boolean(json_object *jobj, json_object *jschema,
				      json_object *joutput_node)
{
	(void)jobj;
	(void)jschema;
	(void)joutput_node;
	// printf("%s\n", __func__);
	// _schemavalidator_output_apply_result(joutput_node, SCHEMAVALIDATOR_ERR_VALID);
	return SCHEMAVALIDATOR_ERR_VALID;
}

int _schemavalidator_validate_instance(json_object *jobj, json_object *jschema,
				       json_object *joutput_node)
{
	int err;
	// printf("--validate instance--\n");
	// printf("%s\n", json_object_get_string(jobj));
	// printf("%s\n", json_object_get_string(jschema));

	err = schemavalidator_check_bool(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_type(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_const(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	err = _schemavalidator_check_enums(jobj, jschema, joutput_node);
	if (err) {
		return err;
	}

	json_type type = json_object_get_type(jobj);

	if (type == json_type_object) {
		return _schemavalidator_validate_object(jobj, jschema,
							joutput_node);
	}
	if (type == json_type_array) {
		return _schemavalidator_validate_array(jobj, jschema,
						       joutput_node);
	}
	if (type == json_type_string) {
		return _schemavalidator_validate_string(jobj, jschema,
							joutput_node);
	}
	if (type == json_type_boolean) {
		return _schemavalidator_validate_boolean(jobj, jschema,
							 joutput_node);
	}
	if (type == json_type_int) {
		return _schemavalidator_validate_integer(jobj, jschema,
							 joutput_node);
	}
	if (type == json_type_double) {
		return _schemavalidator_validate_double(jobj, jschema,
							joutput_node);
	}
	if (type == json_type_null) {
		return SCHEMAVALIDATOR_ERR_VALID;
	}
	printf("%s: WARN: type %d not handled\n", __func__, type);

	return SCHEMAVALIDATOR_ERR_VALID;
}

int schemavalidator_validate(json_object *jobj, json_object *jschema)
{
	json_object *joutput = _schemavalidator_output_create_node("root");
	int err = _schemavalidator_validate_instance(jobj, jschema, joutput);
	_schemavalidator_output_apply_result(joutput, err);

	if (joutput) {
		//printf("Basic Output: %s\n", json_object_get_string(joutput));
		_schemavalidator_output_print_errors(joutput);
	}

	if (joutput) {
		json_object_put(joutput);
	}
	return err;
}
