# Extending `cper-generator` With OEM Sections

Much like `cper-parse`, `cper-generator` supports the addition of arbitrary OEM
sections as extensions. This document details how an OEM section generator could
be added to the `cper-generate` project from a stock version.

## Creating a Section Generator

The first step is to create the generator itself. To do this, you should create
a function predefinition inside `sections/gen-section.h` as shown below, and
then create a C file within `sections/` to house your generation code. For the
sake of example, we will create a generator for a fake OEM section
"myVendorSection".

_sections/gen-section.h_:

```c
//Section generator function predefinitions.
...
size_t generate_section_cxl_protocol(void** location);
size_t generate_section_cxl_component(void** location);
size_t generate_section_myvendor(void** location);
```

_sections/gen-myvendor.c_:

```c
/**
 * Functions for generating pseudo-random MyVendor error sections.
 *
 * Author: author@example.com
 **/

#include <stdlib.h>

size_t generate_section_myvendor(void** location)
{
    //...
}
```

## Adding a Section GUID

To identify our section for parsing, we must define a section GUID within
`edk/Cper.h` and `edk/Cper.c` respectively. This is the same step taken when
adding an OEM extension to `cper-parse`, so if you've already done this, you do
not need to repeat it again.

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

## Adding a Generator Definition

Now that a GUID and generation function are created for our section, we can
finally add it to the generator definitions for `cper-generate`. To do this,
edit `sections/gen-section.c` and add your generator definition to the
`generator_definitions` array. The second string parameter here is the shortcode
used for generating your section, and must contain **no spaces** (this is also
asserted via. GTest).

```c
/**
 * Describes available section generators to the CPER generator.
 *
 * Author: Lawrence.Tang@arm.com
 **/
#include "gen-section.h"

CPER_GENERATOR_DEFINITION generator_definitions[] = {
    ...
    {&gEfiCxlVirtualSwitchErrorSectionGuid, "cxlcomponent-vswitch", generate_section_cxl_component},
    {&gEfiCxlMldPortErrorSectionGuid, "cxlcomponent-mld", generate_section_cxl_component},
    {&gMyVendorSectionGuid, "myvendor", generate_section_myvendor},
};
```

Once this is complete, after a `cmake .` and `make`, your section should be
available to generate through `cper-generate` and `libcper-generate`.
