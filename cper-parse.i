% module cperparse %
	{
#include <libcper/cper-parse.h>
#include <json.h>
#include <stdio.h>
		%
	}

	//Library function declarations for module export.
	json_object *cper_to_ir(FILE *cper_file);
void ir_to_cper(json_object *ir, FILE *out);

//JSON function symbol export.
const char *json_object_to_json_string(struct json_object *obj);
struct json_object *json_object_from_file(const char *filename);
struct json_object *json_tokener_parse(const char *str);
