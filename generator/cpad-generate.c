/**
 * Describes functions for generating pseudo-random specification compliant CPAD records.
 *
 * Author: Lawrence.Tang@arm.com
 *         drewwalton@microsoft.com
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcper/log.h>
#include <libcper/Cpad.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-cpad-section.h>
#include <libcper/generator/cpad-generate.h>

CPAD_SECTION_DESCRIPTOR *generate_cpad_section_descriptor(char *type,
							  UINT16 action_id,
							  const size_t *lengths,
							  int index,
							  int num_sections);
size_t generate_cpad_section(void **location, char *type);
UINT8 generate_random_confidence();
CPAD_URGENCY_BITFIELD generate_random_urgency();


//Generates a CPAD record with the given section types, outputting to the given stream.
// Assumes that PlatformID, PartitionID and TimeStamp are all valid (Validation bits set).
void generate_cpad_record(char **types, UINT16 *action_ids, UINT16 num_sections,
			  FILE *out)
{
	//Generate the sections.
	void *sections[num_sections];
	size_t section_lengths[num_sections];
	for (int i = 0; i < num_sections; i++) {
		section_lengths[i] = generate_cpad_section(sections + i,
							   types[i]);
		if (section_lengths[i] == 0) {
			//Error encountered, exit.
			printf("Error encountered generating section %d of type '%s', length returned zero.\n",
			       i + 1, types[i]);
			return;
		}
	}

	//Generate the header 
	CPAD_HEADER *header = (CPAD_HEADER *)calloc(1, sizeof(CPAD_HEADER));
	header->SignatureStart = CPAD_SIGNATURE_START;
    header->Revision = CPAD_REVISION;
	header->SignatureEnd = CPAD_SIGNATURE_END;
    header->SectionCount = num_sections;
    header->Urgency = (CPAD_URGENCY_BITFIELD){0};  //set later depending on section urgencies
    header->Confidence = 0;                        //set later depending on section confidences
    header->ValidationBits = 0x7; //PlatformID, PartitionID, TimeStamp valid
    // RecordLength filled later
	generate_random_timestamp(&header->TimeStamp);
    header->PlatformID = generate_random_guid();
    header->PartitionID = generate_random_guid();
    header->CreatorID = generate_random_guid();
    header->NotificationType = generate_random_guid();
	header->RecordID = cper_rand64();
    header->Flags = 0; // These are reserved

  
	//Generate the section descriptors given the number of sections.
	CPAD_SECTION_DESCRIPTOR *section_descriptors[num_sections];
	for (int i = 0; i < num_sections; i++) {
		UINT16 action_id = (action_ids != NULL) ? action_ids[i] : 0;
		section_descriptors[i] = generate_cpad_section_descriptor(
			types[i], action_id, section_lengths, i, num_sections);
        if (section_descriptors[i]->Urgency.Urgent) {
            header->Urgency.Urgent = 1; // If any section is urgent, set header urgent
        }
        if (section_descriptors[i]->Confidence > header->Confidence) {
            header->Confidence = section_descriptors[i]->Confidence; // Set header confidence to max of any section's confidence
        }   
	}

	//Calculate total length of structure, set in header.
	size_t total_len = sizeof(CPAD_HEADER);
	for (int i = 0; i < num_sections; i++) {
		total_len += section_lengths[i];
	}
	total_len += num_sections * sizeof(CPAD_SECTION_DESCRIPTOR);
	header->RecordLength = (UINT32)total_len;

	//Write to stream in order, free all resources.
	fwrite(header, sizeof(CPAD_HEADER), 1, out);
	fflush(out);
	free(header);
	for (int i = 0; i < num_sections; i++) {
		fwrite(section_descriptors[i], sizeof(CPAD_SECTION_DESCRIPTOR),
		       1, out);
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
void generate_single_cpad_section_record(char *type, UINT16 action_id, FILE *out)
{
	//Generate a section.
	void *section = NULL;
	size_t section_len = generate_cpad_section(&section, type);

	//Generate a descriptor, correct the offset.
	CPAD_SECTION_DESCRIPTOR *section_descriptor =
		generate_cpad_section_descriptor(type, action_id, &section_len,
						 0, 1);
	section_descriptor->SectionOffset = sizeof(CPAD_SECTION_DESCRIPTOR);

	//Write all to file.
	fwrite(section_descriptor, sizeof(CPAD_SECTION_DESCRIPTOR), 1, out);
	fwrite(section, section_len, 1, out);
	fflush(out);

	//Free remaining resources.
	free(section_descriptor);
	free(section);
}

//Generates a single section descriptor for a section with the given properties.
CPAD_SECTION_DESCRIPTOR *generate_cpad_section_descriptor(char *type,
							  UINT16 action_id,
							  const size_t *lengths,
							  int index,
							  int num_sections)
{

    // Allocate memory for the descriptor and initialize it to zero.
    CPAD_SECTION_DESCRIPTOR *descriptor = (CPAD_SECTION_DESCRIPTOR *)calloc(1, sizeof(CPAD_SECTION_DESCRIPTOR));
    descriptor->Revision = (UINT16)cper_rand();
    descriptor->SecValidMask = 3; // FRuId and FruString valid
    descriptor->Flags = 0; // Reserved
    descriptor->SectionType = (EFI_GUID){0}; //set later
    descriptor->FruId = generate_random_guid();
    descriptor->Urgency = generate_random_urgency();
    descriptor->Confidence = generate_random_confidence(); 
    generate_random_string(descriptor->FruString, sizeof(descriptor->FruString));
    descriptor->ActionID = action_id;

	//Set length, offset from base record.
	descriptor->SectionLength = (UINT32)lengths[index];
	descriptor->SectionOffset =
		sizeof(CPAD_HEADER) +
		(num_sections * sizeof(CPAD_SECTION_DESCRIPTOR));
	for (int i = 0; i < index; i++) {
		descriptor->SectionOffset += lengths[i];
	}

	//If section type is not "unknown", set section type GUID based on type name.
	int section_guid_found = 0;
	if (strcmp(type, "unknown") == 0) {
		section_guid_found = 1;
		descriptor->SectionType = generate_random_guid();
	} else {
		//Find the appropriate GUID for this section name.
		for (size_t i = 0; i < cpad_generator_definitions_len; i++) {
			if (strcmp(type, cpad_generator_definitions[i].ShortName) ==
			    0) {
				memcpy(&descriptor->SectionType,
				       cpad_generator_definitions[i].Guid,
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
size_t generate_cpad_section(void **location, char *type)
{
	//The length of the section.
	size_t length = 0;

	//If the section name is "unknown", simply generate a random bytes section.
	int section_generated = 0;
	int min_size = 8;
	int max_size = 1024;
	if (strcmp(type, "unknown") == 0) {
		length = generate_random_section(location, (cper_rand() % (max_size - min_size + 1)) + min_size);
		section_generated = 1;
	} else {
		//Function defined section, switch on the type, generate accordingly.
		for (size_t i = 0; i < cpad_generator_definitions_len; i++) {
			if (strcmp(type, cpad_generator_definitions[i].ShortName) ==
			    0) {
				length = cpad_generator_definitions[i].Generate(
					location);
				section_generated = 1;
				break;
			}
		}
	}

	//If we didn't find a section generator for the given name, error out.
	if (!section_generated) {
		printf("Undefined section type '%s' given to generate. See 'cpad-generate --help' for command information.\n",
		       type);
		return 0;
	}

	return length;
}


//Create random urgency value for CPAD sections
CPAD_URGENCY_BITFIELD generate_random_urgency()
{
    CPAD_URGENCY_BITFIELD urgency;
    urgency.Urgent = cper_rand() % 2; //0 or 1
    urgency.Resv1 = 0;
    return urgency;
} 

//Create random confidence value for CPAD sections
UINT8 generate_random_confidence()
{
    return (UINT8)(cper_rand() % 101); //0-100%
}
