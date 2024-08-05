# Extending `cper-parse` With OEM Sections

Section definitions within `cper-parse` are entirely modular, and can be easily
modified at compile time to include custom OEM section extensions. This document
will detail how these extensions can be added in from a stock version of the
project.

## Creating a Section Parser

First, we need to create a parser to actually handle the conversion of the
section from CPER -> CPER-JSON and CPER-JSON -> CPER. For the purposes of
example here, we will create a fake CPER section, "myVendorSection", in
`cper-section-myvendor.h` and `cper-section-myvendor.c`.

_sections/cper-section-myvendor.h_:

```c
#ifndef CPER_SECTION_MYVENDOR
#define CPER_SECTION_MYVENDOR

#include <json.h>
#include "../edk/Cper.h"

json_object* cper_section_myvendor_to_ir(void* section, EFI_ERROR_SECTION_DESCRIPTOR* descriptor);
void ir_section_myvendor_to_cper(json_object* section, FILE* out);

#endif
```

_sections/cper-section-myvendor.c_:

```c
/**
 * Describes functions for converting MyVendor sections from binary and JSON format
 * into an intermediate format.
 *
 * Author: author@example.com
 **/
#include <stdio.h>
#include <json.h>
#include "../edk/Cper.h"
#include "cper-section-ccix-per.h"

json_object* cper_section_myvendor_to_ir(void* section, EFI_ERROR_SECTION_DESCRIPTOR* descriptor)
{
    //Define a method here that converts the bytes starting from "section" into JSON IR.
    //The length of the bytes is described in descriptor->Length.
    //...
}

void ir_section_myvendor_to_cper(json_object* section, FILE* out)
{
    //Define a method here that converts the given JSON IR object into CPER binary,
    //writing the output to the provided stream.
    //...
}
```

Once this is done, we can add our section to the parser.

## Adding a Section GUID

To identify our section for parsing, we must define a section GUID within
`edk/Cper.h` and `edk/Cper.c` respectively. They are defined here for shared use
in both `cper-parse` and also `cper-generator` if you wish to write a generation
method for your section.

_edk/Cper.h_:

```c
...
extern EFI_GUID   gEfiCxlVirtualSwitchErrorSectionGuid;
extern EFI_GUID   gEfiCxlMldPortErrorSectionGuid;
extern EFI_GUID   gMyVendorSectionGuid;
```

_edk/Cper.c_:

```c
...
EFI_GUID gEfiCxlVirtualSwitchErrorSectionGuid = { 0x40d26425, 0x3396, 0x4c4d, { 0xa5, 0xda, 0x3d, 0x47, 0x26, 0x3a, 0xf4, 0x25 }};
EFI_GUID gEfiCxlMldPortErrorSectionGuid = { 0x8dc44363, 0x0c96, 0x4710, { 0xb7, 0xbf, 0x04, 0xbb, 0x99, 0x53, 0x4c, 0x3f }};
EFI_GUID gMyVendorSectionGuid = { 0x40d26425, 0x3396, 0x4c4d, { 0xa5, 0xda, 0x3d, 0x47, 0x26, 0x3a, 0xf4, 0x25 }};
```

## Adding a Section Definition

Finally, we need to add a section definition for our section, matching the GUID
to the name and conversion methods. Open `sections/cper-section.c` and add your
definition to the `section_definitions` array, like so:

_sections/cper-section.c_:

```c
/**
 * Describes available sections to the CPER parser.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include "../edk/Cper.h"
#include "cper-section.h"
...
#include "cper-section-myvendor.h"

//Definitions of all sections available to the CPER parser.
CPER_SECTION_DEFINITION section_definitions[] = {
    ...
    {&gMyVendorSectionGuid, "MyVendor Error", cper_section_myvendor_to_ir, ir_section_myvendor_to_cper},
};
```

Now you're done! After a further `cmake .` and `make`, `cper-convert` and all
other conversion libraries included should successfully convert your OEM CPER
section between CPER-JSON and CPER binary.
