/** @file
  GUIDs and definitions used for Common Platform Action Descriptors.

  Copyright (c) 2011 - 2017, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2025, Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Revision Reference:
  GUIDs defined in some future CPAD specification.

**/

/**
 * Extern definitions for EFI GUIDs relating to notification types and error section types.
 **/
#include <libcper/Cpad.h>

// Note that section bodies for CPADs are generally intended to be opaque, containing
// whatever data is needed for a particular RAS API endpoint to take the action. There
// will be very few standard CPAD section bodies.  Almost all of them are expected to
// be proprietary.

//Action section GUIDs.

// Section for passing a message from the RAS API endpoint to the host OS
// e.g. Tell the OS to map out a memory page
EFI_GUID gEfiCpadOsGenericSectionGuid = { 0x6acbe736,
    0xdae8,
    0x11f0,
  { 0xab, 0x29, 0x00, 0x15, 0x5d, 0xf8, 0xf0, 0xe6 }
};

