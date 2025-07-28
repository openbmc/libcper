/**
 * A user-space application linking to the CPER-JSON conversion library which allows for easy
 * conversion between CPER and CPER-JSON formats.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <json.h>
#include <libcper/log.h>
#include <libcper/cper-parse.h>
#include <libcper/json-schema.h>
#include <libcper/Cper.h>
#include <libcper/base64.h>

void cper_to_json(char *in_file, char *out_file, int is_single_section);
void json_to_cper(const char *in_file, const char *out_file);
void print_help(void);

int main(int argc, char *argv[])
{
	cper_set_log_stdio();
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

	// Debug is not used at the moment.  Leave for compatibility.
	(void)debug;
	(void)no_validate;
	(void)specification_file;
	//Run the requested command.
	if (strcmp(argv[1], "to-json") == 0) {
		cper_to_json(input_file, output_file, 0);
	} else if (strcmp(argv[1], "to-json-section") == 0) {
		cper_to_json(input_file, output_file, 1);
	} else if (strcmp(argv[1], "to-cper") == 0) {
		json_to_cper(input_file, output_file);
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

	fseek(cper_file, 0, SEEK_END);
	long fsize = ftell(cper_file);
	fseek(cper_file, 0, SEEK_SET);

	char *fbuff = malloc(fsize);
	size_t readsize = fread(fbuff, 1, (long)fsize, cper_file);
	if (readsize != (size_t)fsize) {
		printf("Could not read CPER file '%s', read returned %zu bytes.\n",
		       in_file, readsize);
		return;
	}

	if (!is_single_section && !header_valid(fbuff, readsize)) {
		// Check if it's base64 encoded
		int32_t decoded_len = 0;
		UINT8 *decoded = base64_decode(fbuff, readsize, &decoded_len);
		if (decoded == NULL) {
			printf("base64 decode failed for CPER file '%s'.\n",
			       in_file);
			free(fbuff);
			free(decoded);
			return;
		}
		if (!header_valid((const char *)decoded, decoded_len)) {
			printf("Invalid CPER file '%s'.\n", in_file);
			free(fbuff);
			free(decoded);
			return;
		}
		// Swap the buffer to the base64 decoded buffer.
		free(fbuff);
		fbuff = (char *)decoded;

		fsize = decoded_len;
		decoded = NULL;
	}

	//Convert.
	json_object *ir;
	if (is_single_section) {
		ir = cper_buf_single_section_to_ir((UINT8 *)fbuff, readsize);
	} else {
		ir = cper_buf_to_ir((UINT8 *)fbuff, fsize);
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
void json_to_cper(const char *in_file, const char *out_file)
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

	//Open a read for the output file.
	FILE *cper_file = fopen(out_file, "w");
	if (cper_file == NULL) {
		printf("Could not open output file '%s', file handle returned null.\n",
		       out_file);
		json_object_put(ir);
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
