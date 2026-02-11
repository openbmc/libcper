/**
 * A user-space application for generating pseudo-random specification compliant CPAD records.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/

// FIXME: add ability to specify PlatformID, PartitionID, CreatorID - primary CPAD coordinates

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcper/log.h>
#include <libcper/Cpad.h>
#include <libcper/generator/cpad-generate.h>
#include <libcper/generator/sections/gen-cpad-section.h>
#include <libcper/generator/gen-utils.h>

void print_help();
UINT16 generate_random_action_id();


int main(int argc, char *argv[])
{
	cper_set_log_stdio();
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
    
    // [NEW] Variables for Action IDs
    char **action_ids = NULL;
    UINT16 num_action_ids = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--out") == 0 && i < argc - 1) {
			out_file = argv[i + 1];
			i++;
		} else if (strcmp(argv[i], "--single-section") == 0 &&
			   i < argc - 1) {
			single_section = argv[i + 1];
			i++;
		
        // [NEW] Parsing logic for --action-ids
		} else if (strcmp(argv[i], "--action-ids") == 0 && i < argc - 1) {
			// Parse arguments until the next flag (starting with --) or end of args
			int j = i + 1;
			while (j < argc && strncmp(argv[j], "--", 2) != 0) {
				j++;
			}
			num_action_ids = j - (i + 1);

			if (num_action_ids > 0) {
				action_ids = malloc(sizeof(char *) * num_action_ids);
				for (int k = 0; k < num_action_ids; k++) {
					action_ids[k] = argv[i + 1 + k];
				}
				i = j - 1; // Advance main loop index
			} else {
				printf("Flag --action-ids provided but no IDs followed.\n");
				return -1;
			}

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
			printf("Unrecognised argument '%s'. For command information, refer to 'cpad-generate --help'.\n",
			       argv[i]);
			return -1;
		}
	}

	//If no output file passed as argument, exit.
	if (out_file == NULL) {
		printf("No output file provided. For command information, refer to 'cpad-generate --help'.\n");
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
		// [NEW] Cleanup
		if (action_ids) {
			free(action_ids);
		}
		return -1;
	}

    // [NEW] Validate that action ID count matches section count
    if (action_ids != NULL) {
        UINT16 expected_count = (single_section != NULL) ? 1 : num_sections;
        if (num_action_ids != expected_count) {
            printf("Error: Number of action IDs (%d) does not match number of sections (%d).\n", 
                   num_action_ids, expected_count);
            if (sections) free(sections);
            if (action_ids) free(action_ids);
            fclose(cper_file);
            return -1;
        }
    }

    // Convert string IDs to UINT16 array for the generator
    UINT16 *action_ids_u16 = malloc(sizeof(UINT16) * num_sections);
    if (action_ids != NULL) {
        for (int k = 0; k < num_sections; k++) {
            // strtoul with base 0 handles both decimal (123) and hex (0x7B)
            action_ids_u16[k] = (UINT16)strtoul(action_ids[k], NULL, 0);
        }
    } else {

        // Generate random Action IDs if none were specified
        for (int k = 0; k < num_sections; k++) {
            action_ids_u16[k] = generate_random_action_id();
        }
    }

    //Which type are we generating?
    if (single_section != NULL && sections == NULL) {
        generate_single_cpad_section_record(single_section, action_ids_u16[0], cper_file);

    } else if (sections != NULL && single_section == NULL) {
        // [MODIFIED] Pass the array of action IDs
        generate_cpad_record(sections, action_ids_u16, num_sections, cper_file);

    } else {
        //Invalid arguments.
        printf("Invalid argument. Either both '--sections' and '--single-section' were set, or neither. For command information, refer to 'cper-generate --help'.\n");
        if (sections) free(sections);
        if (action_ids) free(action_ids);
        if (action_ids_u16) free(action_ids_u16);
        fclose(cper_file);
        return -1;
    }

    //Close & free remaining resources.
    fclose(cper_file);
    if (sections != NULL) {
        free(sections);
    }
    // [NEW] Cleanup
    if (action_ids != NULL) {
        free(action_ids);
    }
    if (action_ids_u16 != NULL) {
        free(action_ids_u16);
    }
}

//Prints command help for this CPER generator.
void print_help()
{
    // [MODIFIED] Update help text
    printf(":: --out cpad.file [--action-ids id1 ...] [--sections section1 ...] [--single-section sectiontype]\n");
    printf("\tGenerates a pseudo-random CPAD file with the provided section types and outputs to the given file name.\n\n");
    printf("\t--action-ids: Optional list of Action IDs (hex or decimal) corresponding to the sections.\n");
    printf("\t              Must appear before --sections if used. Count must match number of sections.\n");
    printf("\tWhen the '--sections' flag is set, all following arguments are section names, and a full CPAD log is generated\n");
    printf("\tcontaining the given sections.\n");
    printf("\tWhen the '--single-section' flag is set, the next argument is the single section that should be generated, and\n");
    printf("\ta single section (no header, only a section descriptor & section) CPAD file is generated.\n\n");
    printf("\tValid section type names are the following:\n");
    for (size_t i = 0; i < cpad_generator_definitions_len; i++) {
        printf("\t\t- %s\n", cpad_generator_definitions[i].ShortName);
    }
    printf("\t\t- unknown\n");
    printf("\n:: --help\n");
    printf("\tDisplays help information to the console.\n");
}

//Creates a random ActionID for CPAD sections
UINT16 generate_random_action_id()
{
	return (UINT16)cper_rand();
}

