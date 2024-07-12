/**
 * Defines utility functions for testing CPER-JSON IR output from the cper-parse library.
 *
 * Author: Lawrence.Tang@arm.com
 **/

#include <cstdio>
#include <cstdlib>
#include "test-utils.hpp"
extern "C" {
#include "../edk/BaseTypes.h"
#include "../generator/cper-generate.h"
}

//Returns a ready-for-use memory stream containing a CPER record with the given sections inside.
FILE *generate_record_memstream(const char **types, UINT16 num_types,
				char **buf, size_t *buf_size,
				int single_section)
{
	//Open a memory stream.
	FILE *stream = open_memstream(buf, buf_size);

	//Generate a section to the stream, close & return.
	if (!single_section) {
		generate_cper_record(const_cast<char **>(types), num_types,
				     stream);
	} else {
		generate_single_section_record(const_cast<char *>(types[0]),
					       stream);
	}
	fclose(stream);

	//Return fmemopen() buffer for reading.
	return fmemopen(*buf, *buf_size, "r");
}
