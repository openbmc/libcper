/** @file
  Processor or Compiler specific defines for all supported processors.

  This file is stand alone self consistent set of definitions.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CPER_BASETYPES_H
#define CPER_BASETYPES_H

#ifdef __cplusplus
extern "C" {
#endif

///
/// 8-byte unsigned value
///
typedef unsigned long long UINT64;
///
/// 8-byte signed value
///
typedef long long INT64;
///
/// 4-byte unsigned value
///
typedef unsigned int UINT32;
///
/// 4-byte signed value
///
typedef int INT32;
///
/// 2-byte unsigned value
///
typedef unsigned short UINT16;
///
/// 2-byte Character.  Unless otherwise specified all strings are stored in the
/// UTF-16 encoding format as defined by Unicode 2.1 and ISO/IEC 10646 standards.
///
typedef unsigned short CHAR16;
///
/// 2-byte signed value
///
typedef short INT16;
///
/// Logical Boolean.  1-byte value containing 0 for FALSE or a 1 for TRUE.  Other
/// values are undefined.
///
typedef unsigned char BOOLEAN;
///
/// 1-byte unsigned value
///
typedef unsigned char UINT8;
///
/// 1-byte Character
///
typedef char CHAR8;
///
/// 1-byte signed value
///
typedef signed char INT8;
//
// Basical data type definitions introduced in UEFI.
//
typedef struct {
	UINT32 Data1;
	UINT16 Data2;
	UINT16 Data3;
	UINT8 Data4[8];
} EFI_GUID;

/**
  Returns a 16-bit signature built from 2 ASCII characters.

  This macro returns a 16-bit value built from the two ASCII characters specified
  by A and B.

  @param  A    The first ASCII character.
  @param  B    The second ASCII character.

  @return A 16-bit value built from the two ASCII characters specified by A and B.

**/
#define SIGNATURE_16(A, B) ((A) | (B << 8))
/**
  Returns a 32-bit signature built from 4 ASCII characters.

  This macro returns a 32-bit value built from the four ASCII characters specified
  by A, B, C, and D.

  @param  A    The first ASCII character.
  @param  B    The second ASCII character.
  @param  C    The third ASCII character.
  @param  D    The fourth ASCII character.

  @return A 32-bit value built from the two ASCII characters specified by A, B,
          C and D.

**/
#define SIGNATURE_32(A, B, C, D)                                               \
	(SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

#ifdef __cplusplus
}
#endif

#endif
