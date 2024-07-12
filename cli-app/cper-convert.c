/**
 * A user-space application linking to the CPER-JSON conversion library which allows for easy
 * conversion between CPER and CPER-JSON formats.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <linux/limits.h>
#include <json.h>
#include "../cper-parse.h"
#include "../json-schema.h"

void cper_to_json(char *in_file, char *out_file, int is_single_section);
void json_to_cper(char *in_file, char *out_file, char *specification_file,
		  char *program_dir, int no_validate, int debug);
void print_help(void);

int main(int argc, char *argv[])
{
	//Print help if requested.
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		print_help();
		return 0;
	}

	//Ensure at least two arguments are present.
	if (argc < 3) {
		printf("Invalid number of arguments. See 'cper-convert --help' for command information.\n");
		return -1;
	}

	//Parse the command line arguments.
	char *input_file = argv[2];
	char *output_file = NULL;
	char *specification_file = NULL;
	int no_validate = 0;
	int debug = 0;
	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--out") == 0 && i < argc - 1) {
			//Output file.
			output_file = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "--specification") == 0 &&
			   i < argc - 1) {
			//Specification file.
			specification_file = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "--no-validate") == 0) {
			//No validation to be used.
			//Invalidates specification file.
			specification_file = NULL;
			no_validate = 1;
		} else if (strcmp(argv[i], "--debug") == 0) {
			//Debug output on.
			debug = 1;
		} else {
			printf("Unrecognised argument '%s'. See 'cper-convert --help' for command information.\n",
			       argv[i]);
		}
	}

	//Run the requested command.
	if (strcmp(argv[1], "to-json") == 0) {
		cper_to_json(input_file, output_file, 0);
	} else if (strcmp(argv[1], "to-json-section") == 0) {
		cper_to_json(input_file, output_file, 1);
	} else if (strcmp(argv[1], "to-cper") == 0) {
		json_to_cper(input_file, output_file, specification_file,
			     argv[0], no_validate, debug);
	} else {
		printf("Unrecognised argument '%s'. See 'cper-convert --help' for command information.\n",
		       argv[1]);
		return -1;
	}

	return 0;
}

//Command for converting a provided CPER log file or CPER single section file into JSON.
void cper_to_json(char *in_file, char *out_file, int is_single_section)
{
	//Get a handle for the log file.
	FILE *cper_file = fopen(in_file, "r");
	if (cper_file == NULL) {
		printf("Could not open provided CPER file '%s', file handle returned null.\n",
		       in_file);
		return;
	}

	//Convert.
	json_object *ir;
	if (is_single_section) {
		ir = cper_single_section_to_ir(cper_file);
	} else {
		ir = cper_to_ir(cper_file);
	}
	fclose(cper_file);

	//Output to string.
	const char *json_output =
		json_object_to_json_string_ext(ir, JSON_C_TO_STRING_PRETTY);

	//Check whether there is a "--out" argument, if there is, then output to file instead.
	//Otherwise, just send to console.
	if (out_file == NULL) {
		printf("%s\n", json_output);
		return;
	}

	//Try to open a file handle to the desired output file.
	FILE *json_file = fopen(out_file, "w");
	if (json_file == NULL) {
		printf("Could not get a handle for output file '%s', file handle returned null.\n",
		       out_file);
		return;
	}

	//Write out to file.
	fwrite(json_output, strlen(json_output), 1, json_file);
	fclose(json_file);
}

//Command for converting a provided CPER-JSON JSON file to CPER binary.
void json_to_cper(char *in_file, char *out_file, char *specification_file,
		  char *program_dir, int no_validate, int debug)
{
	//Verify output file exists.
	if (out_file == NULL) {
		printf("No output file provided for 'to-cper'. See 'cper-convert --help' for command information.\n");
		return;
	}

	//Read JSON IR from file.
	json_object *ir = json_object_from_file(in_file);
	if (ir == NULL) {
		printf("Could not read JSON from file '%s', import returned null.\n",
		       in_file);
		return;
	}

	//Validate the JSON against specification, unless otherwise specified.
	if (!no_validate) {
		int using_default_spec_path = 0;

		//Is there a specification file path?
		if (specification_file == NULL) {
			using_default_spec_path = 1;

			//Make the specification path the assumed default (application directory + specification/cper-json.json).
			specification_file = malloc(PATH_MAX);
			char *dir = dirname(program_dir);
			strcpy(specification_file, dir);
			strcat(specification_file,
			       "/specification/cper-json.json");
		}

		//Enable debug mode if indicated.
		if (debug) {
			validate_schema_debug_enable();
		}

		//Attempt to verify with the the specification.
		char *error_message = malloc(JSON_ERROR_MSG_MAX_LEN);
		int success = validate_schema_from_file(specification_file, ir,
							error_message);

		//Free specification path (if necessary).
		if (using_default_spec_path) {
			free(specification_file);
		}

		//If failed, early exit before conversion.
		if (!success) {
			printf("JSON format validation failed: %s\n",
			       error_message);
			free(error_message);
			return;
		}
		free(error_message);
	}

	//Open a read for the output file.
	FILE *cper_file = fopen(out_file, "w");
	if (cper_file == NULL) {
		printf("Could not open output file '%s', file handle returned null.\n",
		       out_file);
		return;
	}

	//Detect the type of CPER (full log, single section) from the IR given.
	//Run the converter accordingly.
	if (json_object_object_get(ir, "header") != NULL) {
		ir_to_cper(ir, cper_file);
	} else {
		ir_single_section_to_cper(ir, cper_file);
	}
	fclose(cper_file);
	json_object_put(ir);
}

//Command for printing help information.
void print_help(void)
{
	printf(":: to-json cper.file [--out file.name]\n");
	printf("\tConverts the provided CPER log file into JSON, by default writing to stdout. If '--out' is specified,\n");
	printf("\tThe outputted JSON will be written to the provided file name instead.\n");
	printf("\n:: to-json-section cper.section.file [--out file.name]\n");
	printf("\tConverts the provided single CPER section descriptor & section file into JSON, by default writing to stdout.\n");
	printf("\tOtherwise behaves the same as 'to-json'.\n");
	printf("\n:: to-cper cper.json --out file.name [--no-validate] [--debug] [--specification some/spec/path.json]\n");
	printf("\tConverts the provided CPER-JSON JSON file into CPER binary. An output file must be specified with '--out'.\n");
	printf("\tWill automatically detect whether the JSON passed is a single section, or a whole file,\n");
	printf("\tand output binary accordingly.\n\n");
	printf("\tBy default, the provided JSON will try to be validated against a specification. If no specification file path\n");
	printf("\tis provided with '--specification', then it will default to 'argv[0] + /specification/cper-json.json'.\n");
	printf("\tIf the '--no-validate' argument is set, then the provided JSON will not be validated. Be warned, this may cause\n");
	printf("\tpremature exit/unexpected behaviour in CPER output.\n\n");
	printf("\tIf '--debug' is set, then debug output for JSON specification parsing will be printed to stdout.\n");
	printf("\n:: --help\n");
	printf("\tDisplays help information to the console.\n");
}
