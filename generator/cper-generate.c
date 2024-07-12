/**
 * Describes functions for generating pseudo-random specification compliant CPER records.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../edk/Cper.h"
#include "gen-utils.h"
#include "sections/gen-section.h"
#include "cper-generate.h"

EFI_ERROR_SECTION_DESCRIPTOR *generate_section_descriptor(char *type,
							  const size_t *lengths,
							  int index,
							  int num_sections);
size_t generate_section(void **location, char *type);

//Generates a CPER record with the given section types, outputting to the given stream.
void generate_cper_record(char **types, UINT16 num_sections, FILE *out)
{
	//Initialise randomiser.
	init_random();

	//Generate the sections.
	void *sections[num_sections];
	size_t section_lengths[num_sections];
	for (int i = 0; i < num_sections; i++) {
		section_lengths[i] = generate_section(sections + i, types[i]);
		if (section_lengths[i] == 0) {
			//Error encountered, exit.
			printf("Error encountered generating section %d of type '%s', length returned zero.\n",
			       i + 1, types[i]);
			return;
		}
	}

	//Generate the header given the number of sections.
	EFI_COMMON_ERROR_RECORD_HEADER *header =
		(EFI_COMMON_ERROR_RECORD_HEADER *)calloc(
			1, sizeof(EFI_COMMON_ERROR_RECORD_HEADER));
	header->SignatureStart = 0x52455043; //CPER
	header->SectionCount = num_sections;
	header->SignatureEnd = 0xFFFFFFFF;
	header->Flags = 4; //HW_ERROR_FLAGS_SIMULATED
	header->RecordID = (UINT64)rand();
	header->ErrorSeverity = rand() % 4;

	//Generate a valid timestamp.
	header->TimeStamp.Century = int_to_bcd(rand() % 100);
	header->TimeStamp.Year = int_to_bcd(rand() % 100);
	header->TimeStamp.Month = int_to_bcd(rand() % 12 + 1);
	header->TimeStamp.Day = int_to_bcd(rand() % 31 + 1);
	header->TimeStamp.Hours = int_to_bcd(rand() % 24 + 1);
	header->TimeStamp.Seconds = int_to_bcd(rand() % 60);

	//Turn all validation bits on.
	header->ValidationBits = 0x3;

	//Generate the section descriptors given the number of sections.
	EFI_ERROR_SECTION_DESCRIPTOR *section_descriptors[num_sections];
	for (int i = 0; i < num_sections; i++) {
		section_descriptors[i] = generate_section_descriptor(
			types[i], section_lengths, i, num_sections);
	}

	//Calculate total length of structure, set in header.
	size_t total_len = sizeof(EFI_COMMON_ERROR_RECORD_HEADER);
	for (int i = 0; i < num_sections; i++) {
		total_len += section_lengths[i];
	}
	total_len += num_sections * sizeof(EFI_ERROR_SECTION_DESCRIPTOR);
	header->RecordLength = (UINT32)total_len;

	//Write to stream in order, free all resources.
	fwrite(header, sizeof(EFI_COMMON_ERROR_RECORD_HEADER), 1, out);
	fflush(out);
	free(header);
	for (int i = 0; i < num_sections; i++) {
		fwrite(section_descriptors[i],
		       sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1, out);
		fflush(out);
		free(section_descriptors[i]);
	}
	for (int i = 0; i < num_sections; i++) {
		fwrite(sections[i], section_lengths[i], 1, out);
		fflush(out);
		free(sections[i]);
	}
}

//Generates a single section record for the given section, and outputs to file.
void generate_single_section_record(char *type, FILE *out)
{
	//Generate a section.
	void *section = NULL;
	size_t section_len = generate_section(&section, type);

	//Generate a descriptor, correct the offset.
	EFI_ERROR_SECTION_DESCRIPTOR *section_descriptor =
		generate_section_descriptor(type, &section_len, 0, 1);
	section_descriptor->SectionOffset =
		sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

	//Write all to file.
	fwrite(section_descriptor, sizeof(EFI_ERROR_SECTION_DESCRIPTOR), 1,
	       out);
	fwrite(section, section_len, 1, out);
	fflush(out);

	//Free remaining resources.
	free(section_descriptor);
	free(section);
}

//Generates a single section descriptor for a section with the given properties.
EFI_ERROR_SECTION_DESCRIPTOR *generate_section_descriptor(char *type,
							  const size_t *lengths,
							  int index,
							  int num_sections)
{
	EFI_ERROR_SECTION_DESCRIPTOR *descriptor =
		(EFI_ERROR_SECTION_DESCRIPTOR *)generate_random_bytes(
			sizeof(EFI_ERROR_SECTION_DESCRIPTOR));

	//Set reserved bits to zero.
	descriptor->Resv1 = 0;
	descriptor->SectionFlags &= 0xFF;

	//Validation bits all set to 'on'.
	descriptor->SecValidMask = 0x3;

	//Set severity.
	descriptor->Severity = rand() % 4;

	//Set length, offset from base record.
	descriptor->SectionLength = (UINT32)lengths[index];
	descriptor->SectionOffset =
		sizeof(EFI_COMMON_ERROR_RECORD_HEADER) +
		(num_sections * sizeof(EFI_ERROR_SECTION_DESCRIPTOR));
	for (int i = 0; i < index; i++) {
		descriptor->SectionOffset += lengths[i];
	}

	//Ensure the FRU text is not null terminated early.
	for (int i = 0; i < 20; i++) {
		if (descriptor->FruString[i] == 0x0) {
			descriptor->FruString[i] = rand() % 127 + 1;
		}

		//Null terminate last byte.
		if (i == 19) {
			descriptor->FruString[i] = 0x0;
		}
	}

	//If section type is not "unknown", set section type GUID based on type name.
	int section_guid_found = 0;
	if (strcmp(type, "unknown") == 0) {
		section_guid_found = 1;
	} else {
		//Find the appropriate GUID for this section name.
		for (size_t i = 0; i < generator_definitions_len; i++) {
			if (strcmp(type, generator_definitions[i].ShortName) ==
			    0) {
				memcpy(&descriptor->SectionType,
				       generator_definitions[i].Guid,
				       sizeof(EFI_GUID));
				section_guid_found = 1;
				break;
			}
		}
	}

	//Undefined section, show error.
	if (!section_guid_found) {
		//Undefined section, show error.
		printf("Undefined section type '%s' provided. See 'cper-generate --help' for command information.\n",
		       type);
		return 0;
	}

	return descriptor;
}

//Generates a single CPER section given the string type.
size_t generate_section(void **location, char *type)
{
	//The length of the section.
	size_t length = 0;

	//If the section name is "unknown", simply generate a random bytes section.
	int section_generated = 0;
	if (strcmp(type, "unknown") == 0) {
		length = generate_random_section(location, rand() % 256);
		section_generated = 1;
	} else {
		//Function defined section, switch on the type, generate accordingly.
		for (size_t i = 0; i < generator_definitions_len; i++) {
			if (strcmp(type, generator_definitions[i].ShortName) ==
			    0) {
				length = generator_definitions[i].Generate(
					location);
				section_generated = 1;
				break;
			}
		}
	}

	//If we didn't find a section generator for the given name, error out.
	if (!section_generated) {
		printf("Undefined section type '%s' given to generate. See 'cper-generate --help' for command information.\n",
		       type);
		return 0;
	}

	return length;
}
