/** @file
  GUIDs and definitions used for Common Platform Action Descriptors.

  Copyright (c) 2011 - 2017, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) 2025, Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Revision Reference:
  CPAD error sections defined in OCP RAS API Specification v0.9

**/

#ifndef CPAD_H
#define CPAD_H

#include <libcper/BaseTypes.h>
#include <libcper/common-utils.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

#define CPAD_SIGNATURE_START SIGNATURE_32('C', 'P', 'A', 'D')
#define CPAD_SIGNATURE_END	 0xFFFFFFFF // per CPER & CPAD specs

#define CPAD_REVISION 0x0009 //v0.9

///
/// Action Urgency in CPAD headers and section descriptors
///@{
typedef struct {
	UINT8 Urgent : 1;
	UINT8 Resv1 : 7;
} CPAD_URGENCY_BITFIELD;
///@}

// Action Confidence
#define MAX_CONFIDENCE_LEVEL 100

///
/// The validation bit mask indicates the validity of the following fields
/// in Error Record Header.
///@{
#define CPAD_HEADER_PLATFORM_ID_VALID  0   // FIXME: this might be broken in ir-parse-cpad.c Check for use of ValidationTypes
#define CPAD_HEADER_TIME_STAMP_VALID   1
#define CPAD_HEADER_PARTITION_ID_VALID 2
///@}

///
/// Timestamp is precise if this bit is set and correlates to the time of the
/// error event.  Used in the CPAD TimeStamp.Flag field.
///
#define CPAD_TIME_STAMP_PRECISE BIT0 

///
/// Hexadecimal string representation of a 64bit integer
/// 16 digits + 2 char + 1 null termination
///
#define CPAD_UINT64_HEX_STRING_LEN 19


///
/// GUID value associating the action with its type.
///
/// FIXME: This GUID is a placeholder.  This field does not make sense to have
///        in the header.  It seems more appropriate to have it in the section
///        descriptors.
///
///@{
#define CPAD_NOTIFICATION_TYPE_TBD_GUID                                    \
	{ 0x4a7c0b16,                                                          \
	  0x00D2,                                                              \
	  0x48fc,                                                              \
	  { 0xa6, 0x65, 0xa5, 0xcd, 0x0c, 0x67, 0x49, 0x51 } }
///@}

///
/// CPAD Header Flags
///@{
#define RESERVED_SET_TO_ZERO         0x00000000
///@}

///
/// Common Platform Action Descriptor(CPAD) header
///
typedef struct {
	UINT32 SignatureStart;
	UINT16 Revision;
	UINT32 SignatureEnd;
	UINT16 SectionCount;
	CPAD_URGENCY_BITFIELD Urgency;
    UINT8 Confidence;
    UINT16 Reserved1;
	UINT32 ValidationBits;
	UINT32 RecordLength;
	EFI_ERROR_TIME_STAMP TimeStamp;
	EFI_GUID PlatformID;
	EFI_GUID PartitionID;
	EFI_GUID CreatorID;
	EFI_GUID NotificationType;
	UINT64 RecordID;
	UINT32 Flags;
	UINT8 Reserved2[20];
	///
	/// An array of SectionCount descriptors for the associated
	/// sections. The number of valid sections is equivalent to the
	/// SectionCount. The buffer size of the record may include
	/// more space to dynamically add additional Section
	/// Descriptors to the error record.
	///
} CPAD_HEADER;

#define CPAD_SECTION_REVISION 0x0009

///
/// Validity Fields in Error Section Descriptor.
///
#define CPAD_SECTION_FRU_ID_VALID	   0
#define CPAD_SECTION_FRU_STRING_VALID  1

///
/// Flag field contains information that describes the error section
/// in Error Section Descriptor.
///
//#define CPAD_SECTION_FLAGS_RESERVED			        BIT0

///
/// CPAD Section Descriptor - each section represents an action to be taken.
///
typedef struct {
	UINT32 SectionOffset;
	UINT32 SectionLength;
	UINT16 Revision;
	UINT8 SecValidMask;
	UINT8 Reserved1;
	UINT32 Flags;
	EFI_GUID SectionType;
	EFI_GUID FruId;
    CPAD_URGENCY_BITFIELD Urgency;
    UINT8 Confidence;
    UINT16 Reserved2;
	CHAR8 FruString[20];
    UINT16 ActionID;
} CPAD_SECTION_DESCRIPTOR;

// CPAD Section Action ID definitions
// FIXME: These are placeholders for demonstration purposes only.
//        Actual Action IDs to be defined by OCP RAS API working group.
#define CPAD_ACTION_DO_NOTHING 				0x0000  // Can be used to test CPAD routing
#define CPAD_ACTION_RESET_NO_POWER_CYCLE	0x0001
#define CPAD_ACTION_POWER_CYCLE				0x0002
#define CPAD_ACTION_RESEAT_PART				0x0003
#define CPAD_ACTION_SHUFFLE_PART			0x0004  // May be only used for diagnostic testing
#define CPAD_ACTION_REPLACE_PART			0x0005
#define CPAD_ACTION_INJECT_ERROR			0x0006 

// Proprietary Action IDs start here
// These IDs are not defined by OCP RAS API working group and are not
// named in this header file. They will be printed as numeric values only.
#define FIRST_PROPRIETARY_ACTION_ID 		0x8000

// CPAD Section Definitions are in cpad-section.h and cpad-section.c
// GUIDs for standard sections are in Cpad-guid.c
extern EFI_GUID gEfiCpadOsGenericSectionGuid;

///
/// OS Generic Action Section
/// This is not presently part of the CPAD spec and is shown here as a
/// possible way to pass actions to the OS.
///
typedef struct {
	UINT64 Operation;
	UINT64 TargetAddr;
	UINT64 Parameter1;
	UINT64 Parameter2;
	UINT64 Parameter3;
} OS_GENERIC_CPAD_DATA;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif // __CPAD_H__
