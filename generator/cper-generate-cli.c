/**
 * A user-space application for generating pseudo-random specification compliant CPER records.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../edk/Cper.h"
#include "cper-generate.h"
#include "sections/gen-section.h"

void print_help();

int main(int argc, char *argv[])
{
	//If help requested, print help.
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		print_help();
		return 0;
	}

	//Parse the command line arguments.
	char *out_file = NULL;
	char *single_section = NULL;
	char **sections = NULL;
	UINT16 num_sections = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--out") == 0 && i < argc - 1) {
			out_file = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "--single-section") == 0 &&
			   i < argc - 1) {
			single_section = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "--sections") == 0 && i < argc - 1) {
			//All arguments after this must be section names.
			num_sections = argc - i - 1;
			sections = malloc(sizeof(char *) * num_sections);
			i++;

			for (int j = i; j < argc; j++) {
				sections[j - i] = argv[j];
			}
			break;
		} else {
			printf("Unrecognised argument '%s'. For command information, refer to 'cper-generate --help'.\n",
			       argv[i]);
			return -1;
		}
	}

	//If no output file passed as argument, exit.
	if (out_file == NULL) {
		printf("No output file provided. For command information, refer to 'cper-generate --help'.\n");
		if (sections) {
			free(sections);
		}
		return -1;
	}

	//Open a file handle to write output.
	FILE *cper_file = fopen(out_file, "w");
	if (cper_file == NULL) {
		printf("Could not get a handle for output file '%s', file handle returned null.\n",
		       out_file);
		if (sections) {
			free(sections);
		}
		return -1;
	}

	//Which type are we generating?
	if (single_section != NULL && sections == NULL) {
		generate_single_section_record(single_section, cper_file);
	} else if (sections != NULL && single_section == NULL) {
		generate_cper_record(sections, num_sections, cper_file);
	} else {
		//Invalid arguments.
		printf("Invalid argument. Either both '--sections' and '--single-section' were set, or neither. For command information, refer to 'cper-generate --help'.\n");
		if (sections) {
			free(sections);
		}
		return -1;
	}

	//Close & free remaining resources.
	fclose(cper_file);
	if (sections != NULL) {
		free(sections);
	}
}

//Prints command help for this CPER generator.
void print_help()
{
	printf(":: --out cper.file [--sections section1 ...] [--single-section sectiontype]\n");
	printf("\tGenerates a pseudo-random CPER file with the provided section types and outputs to the given file name.\n\n");
	printf("\tWhen the '--sections' flag is set, all following arguments are section names, and a full CPER log is generated\n");
	printf("\tcontaining the given sections.\n");
	printf("\tWhen the '--single-section' flag is set, the next argument is the single section that should be generated, and\n");
	printf("\ta single section (no header, only a section descriptor & section) CPER file is generated.\n\n");
	printf("\tValid section type names are the following:\n");
	for (size_t i = 0; i < generator_definitions_len; i++) {
		printf("\t\t- %s\n", generator_definitions[i].ShortName);
	}
	printf("\t\t- unknown\n");
	printf("\n:: --help\n");
	printf("\tDisplays help information to the console.\n");
}
