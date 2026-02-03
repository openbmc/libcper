/**
 * See: https://developer.arm.com/documentation/den0085/latest/
 * Minimal parser/generator for ARM RAS CPER section (Table 20/21)
 * Author: prachotan.bathi@arm.com
 */
#include <libcper/Cper.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <libcper/base64.h>
#include <libcper/cper-utils.h>
#include <libcper/sections/cper-section-arm-ras.h>
#include <libcper/log.h>

/*
 * Fixed-size fields in EFI_ARM_RAS_NODE.
 *
 * IPInstance: 16 bytes, serialized as a 32-character hex string.
 * IPType:     24 bytes, serialized as a 48-character hex string.
 * UserData:   16 bytes, but we emit up to 15 chars to keep a terminator.
 */
#define ARM_RAS_IP_INSTANCE_BYTES 16
#define ARM_RAS_IP_TYPE_BYTES	  24
#define ARM_RAS_USER_DATA_BYTES	  16

#define ARM_RAS_HEX_CHARS_PER_BYTE 2
#define ARM_RAS_KEY_HEX_BYTES	   16
#define ARM_RAS_KEY_HEX_LEN	   (ARM_RAS_KEY_HEX_BYTES * ARM_RAS_HEX_CHARS_PER_BYTE)
#define ARM_RAS_IP_INSTANCE_HEX_LEN                                            \
	(ARM_RAS_IP_INSTANCE_BYTES * ARM_RAS_HEX_CHARS_PER_BYTE)
#define ARM_RAS_IP_TYPE_HEX_LEN                                                \
	(ARM_RAS_IP_TYPE_BYTES * ARM_RAS_HEX_CHARS_PER_BYTE)

#define ARM_RAS_USER_DATA_MAX_JSON_CHARS (ARM_RAS_USER_DATA_BYTES - 1)

static void arm_ras_set_desc_string_valid(char **desc_string)
{
	if (desc_string) {
		*desc_string = malloc(SECTION_DESC_STRING_SIZE);
		if (*desc_string) {
			snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				 "ARM RAS error occured");
		}
	}
}

static void arm_ras_set_desc_string_invalid(const char *reason,
					    char **desc_string)
{
	if (desc_string) {
		*desc_string = malloc(SECTION_DESC_STRING_SIZE);
		if (*desc_string) {
			snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
				 "ARM RAS (empty): %s",
				 reason ? reason : "unspecified");
		}
	}
}

static bool arm_ras_read_node(EFI_ARM_RAS_NODE *node, const UINT8 *section,
			      UINT32 size, char **desc_string,
			      json_object **root)
{
	char reason[SECTION_DESC_STRING_SIZE];
	*root = json_object_new_object();
	if (size < sizeof(EFI_ARM_RAS_NODE)) {
		cper_print_log("ARM RAS section too small: %u < %zu",
			       (unsigned)size, sizeof(EFI_ARM_RAS_NODE));
		snprintf(reason, sizeof(reason), "invalid/too small %u < %zu",
			 (unsigned)size, sizeof(EFI_ARM_RAS_NODE));
		arm_ras_set_desc_string_invalid(reason, desc_string);
		return false;
	}

	memcpy(node, section, sizeof(*node));
	UINT32 descriptorCount = node->ErrorSyndromeArrayNumEntries;
	UINT64 descBytes = (UINT64)descriptorCount *
			   (UINT64)sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);
	if (descBytes > (UINT64)(size - node->ErrorSyndromeArrayOffset)) {
		cper_print_log("ARM RAS descriptor array out of range");
		snprintf(reason, sizeof(reason),
			 "descriptor array out of range");
		arm_ras_set_desc_string_invalid(reason, desc_string);
		return false;
	}
	if (node->Revision != 1) {
		cper_print_log("Unsupported ARM RAS revision: %u",
			       node->Revision);
		snprintf(reason, sizeof(reason),
			 "unsupported ARM RAS revision: %u", node->Revision);
		arm_ras_set_desc_string_invalid(reason, desc_string);
		return false;
	}

	if (node->ErrorSyndromeArrayOffset < sizeof(EFI_ARM_RAS_NODE) ||
	    node->ErrorSyndromeArrayOffset >= size ||
	    (node->AuxiliaryDataOffset && node->AuxiliaryDataOffset >= size)) {
		cper_print_log("Invalid ARM RAS offsets");
		snprintf(reason, sizeof(reason), "invalid ARM RAS offsets");
		arm_ras_set_desc_string_invalid(reason, desc_string);
		return false;
	}

	return true;
}

static void arm_ras_add_fixed_fields(json_object *root,
				     const EFI_ARM_RAS_NODE *node)
{
	json_object_object_add(root, "revision",
			       json_object_new_uint64(node->Revision));
	json_object_object_add(
		root, "componentType",
		json_object_new_uint64((UINT64)node->ComponentType));
	json_object_object_add(
		root, "errorSyndromeArrayOffset",
		json_object_new_uint64((UINT64)node->ErrorSyndromeArrayOffset));
	json_object_object_add(
		root, "auxDataOffset",
		json_object_new_uint64((UINT64)node->AuxiliaryDataOffset));
	json_object_object_add(
		root, "errorSyndromeArrayNumEntries",
		json_object_new_uint64(
			(UINT64)node->ErrorSyndromeArrayNumEntries));
	json_object_object_add(
		root, "ipInstanceFormat",
		json_object_new_uint64((UINT64)node->IPInstanceFormat));
	json_object_object_add(
		root, "ipTypeFormat",
		json_object_new_uint64((UINT64)node->IPTypeFormat));

	add_bytes_hex(root, "ipInstance", node->IPInstance,
		      ARM_RAS_IP_INSTANCE_BYTES);
	add_bytes_hex(root, "ipType", node->IPType, ARM_RAS_IP_TYPE_BYTES);

	int udLen = 0;
	for (; udLen < ARM_RAS_USER_DATA_BYTES && node->UserData[udLen] != 0;
	     udLen++) {
		;
	}
	if (udLen == ARM_RAS_USER_DATA_BYTES) {
		udLen = ARM_RAS_USER_DATA_MAX_JSON_CHARS;
	}
	add_untrusted_string(root, "userData", (const char *)node->UserData,
			     udLen);
}

static json_object *arm_ras_parse_descriptors(const UINT8 *section,
					      const EFI_ARM_RAS_NODE *node,
					      UINT32 descriptorCount)
{
	json_object *descArrObj = json_object_new_array();
	const UINT8 *desc_ptr = section + node->ErrorSyndromeArrayOffset;

	for (UINT32 i = 0; i < descriptorCount; i++) {
		const UINT8 *cur =
			desc_ptr +
			i * sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);
		EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR d;
		memcpy(&d, cur, sizeof(d));
		json_object *desc = json_object_new_object();
		json_object_object_add(
			desc, "errorRecordIndex",
			json_object_new_uint64(d.ErrorRecordIndex));
		json_object_object_add(
			desc, "rasExtensionRevisionField",
			json_object_new_uint64((d.RasExtensionRevision >> 4) &
					       0x0F));
		json_object_object_add(
			desc, "rasExtensionArchVer",
			json_object_new_uint64(d.RasExtensionRevision & 0x0F));
		json_object_object_add(desc, "errorRecordFeatureRegister",
				       json_object_new_uint64(d.ERR_FR));
		json_object_object_add(desc, "errorRecordControlRegister",
				       json_object_new_uint64(d.ERR_CTLR));
		json_object_object_add(desc, "errorRecordPrimaryStatusRegister",
				       json_object_new_uint64(d.ERR_STATUS));
		json_object_object_add(desc, "errorRecordAddressRegister",
				       json_object_new_uint64(d.ERR_ADDR));
		json_object_object_add(desc, "errorRecordMiscRegister0",
				       json_object_new_uint64(d.ERR_MISC0));
		json_object_object_add(desc, "errorRecordMiscRegister1",
				       json_object_new_uint64(d.ERR_MISC1));
		if (d.RasExtensionRevision) {
			json_object_object_add(
				desc, "errorRecordMiscRegister2",
				json_object_new_uint64(d.ERR_MISC2));
			json_object_object_add(
				desc, "errorRecordMiscRegister3",
				json_object_new_uint64(d.ERR_MISC3));
		}
		json_object_array_add(descArrObj, desc);
	}

	return descArrObj;
}

/*
 * Validate the fixed-size ARM RAS auxiliary header fields.
 */
static bool arm_ras_aux_hdr_valid(const EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr,
				  UINT32 auxLen)
{
	/*
	 * KVP array layout:
	 *   - When there are no entries, the offset must be exactly the
	 *     end of the aux blob.
	 *   - When entries are present, the offset must be somewhere inside
	 *     the aux blob (the upper bound is checked here, the lower
	 *     bound below).
	 */
	bool kvOffsetValid =
		((auxHdr->KeyValuePairArrayEntryCount == 0 &&
		  auxHdr->KeyValuePairArrayOffset ==
			  auxHdr->AuxiliaryDataSize) ||
		 (auxHdr->KeyValuePairArrayOffset < auxHdr->AuxiliaryDataSize));
	/*
	* The spec requires (Table 22):
	*   - Version must be 1
	*   - AuxiliaryDataSize is the total size of the aux block, including
	*     the header itself, and must:
	*       * fit within the remaining section buffer (<= auxLen) and
	*       * be at least large enough to hold the header.
	*/
	return (auxHdr->Version == 1) &&
	       (auxHdr->AuxiliaryDataSize <= auxLen) &&
	       (auxHdr->AuxiliaryDataSize >=
		sizeof(EFI_ARM_RAS_AUX_DATA_HEADER)) &&
	       kvOffsetValid &&
	       (auxHdr->KeyValuePairArrayOffset >=
		sizeof(EFI_ARM_RAS_AUX_DATA_HEADER));
}

static json_object *
arm_ras_aux_emit_header_fields(const EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr)
{
	/* Emit auxiliary header fields in spec order (Table 22):
	 * version, reserved0 (omitted - always zero), addressSpaceArrayEntryCount,
	 * auxiliaryDataSize, keyValuePairArrayOffset, keyValuePairArrayEntryCount,
	 * reserved1 (omitted).
	 */
	json_object *auxStructured = json_object_new_object();
	json_object_object_add(auxStructured, "version",
			       json_object_new_uint64((UINT64)auxHdr->Version));
	json_object_object_add(
		auxStructured, "addressSpaceArrayEntryCount",
		json_object_new_uint64(
			(UINT64)auxHdr->AddressSpaceArrayEntryCount));
	json_object_object_add(
		auxStructured, "auxiliaryDataSize",
		json_object_new_uint64((UINT64)auxHdr->AuxiliaryDataSize));
	json_object_object_add(
		auxStructured, "keyValuePairArrayOffset",
		json_object_new_uint64(
			(UINT64)auxHdr->KeyValuePairArrayOffset));
	json_object_object_add(
		auxStructured, "keyValuePairArrayEntryCount",
		json_object_new_uint64(
			(UINT64)auxHdr->KeyValuePairArrayEntryCount));
	return auxStructured;
}

static bool
arm_ras_aux_parse_contexts(json_object *auxStructured, const UINT8 *aux_ptr,
			   const EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr)
{
	json_object *contexts = json_object_new_array();
	const UINT8 *cursor = aux_ptr + sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
	UINT32 remaining =
		auxHdr->AuxiliaryDataSize - sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
	bool ok = true;

	for (UINT16 ci = 0; ci < auxHdr->AddressSpaceArrayEntryCount; ci++) {
		if (remaining < sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER)) {
			ok = false;
			cper_print_log(
				"ARM RAS Auxiliary Data too small for context header: %u < %zu",
				remaining,
				sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
			break;
		}
		const EFI_ARM_RAS_AUX_CONTEXT_HEADER *ctx =
			(const EFI_ARM_RAS_AUX_CONTEXT_HEADER *)cursor;
		if (ctx->Length < sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER)) {
			ok = false;
			cper_print_log(
				"ARM RAS Auxiliary Context length too small: %u < %zu",
				ctx->Length,
				sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
			break;
		}
		UINT32 needed = sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
				ctx->RegisterArrayEntryCount *
					sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
		if (ctx->Length < needed || needed > remaining) {
			ok = false;
			cper_print_log(
				"ARM RAS Auxiliary Context length too small or exceeds remaining data: %u < %u or %u > %u",
				ctx->Length, needed, needed, remaining);
			break;
		}
		UINT32 afterCtxOffset =
			(UINT32)(cursor - aux_ptr) + ctx->Length;
		if (afterCtxOffset > auxHdr->KeyValuePairArrayOffset) {
			ok = false;
			cper_print_log(
				"ARM RAS Auxiliary Context overlaps KVP array");
			break;
		}

		json_object *ctxObjInstance = json_object_new_object();
		json_object_object_add(
			ctxObjInstance, "length",
			json_object_new_uint64((UINT64)ctx->Length));
		json_object_object_add(
			ctxObjInstance, "flags",
			json_object_new_uint64((UINT64)ctx->Flags));
		json_object_object_add(
			ctxObjInstance, "registerArrayEntryCount",
			json_object_new_uint64(
				(UINT64)ctx->RegisterArrayEntryCount));
		if (ctx->Flags & 0x1) {
			json_object_object_add(
				ctxObjInstance, "addressSpaceIdentifier",
				json_object_new_uint64(
					(UINT64)ctx->AddressSpaceIdentifier));
		}

		json_object *regs = json_object_new_array();
		const EFI_ARM_RAS_AUX_MM_REG_ENTRY *regArr =
			(const EFI_ARM_RAS_AUX_MM_REG_ENTRY
				 *)(cursor +
				    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
		for (UINT16 ri = 0; ri < ctx->RegisterArrayEntryCount; ri++) {
			json_object *r = json_object_new_object();
			json_object_object_add(
				r, "address",
				json_object_new_uint64(
					regArr[ri].RegisterAddress));
			json_object_object_add(
				r, "value",
				json_object_new_uint64(
					regArr[ri].RegisterValue));
			json_object_array_add(regs, r);
		}
		json_object_object_add(ctxObjInstance, "registers", regs);
		json_object_array_add(contexts, ctxObjInstance);

		cursor += ctx->Length;
		remaining -= ctx->Length;
	}

	if (ok) {
		json_object_object_add(auxStructured, "contexts", contexts);
	}

	return ok;
}

int is_mpam(EFI_GUID *key)
{
	if (guid_equal(key, &EFI_ARM_RAS_KVP_UUID_MPAM_PARTID)) {
		return 1;
	}
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	// The exact byte used here is arbitrary.
	return key->Data4[0] % 2;
#endif
	return 0;
}

static void arm_ras_aux_parse_kvps(json_object *auxStructured,
				   const UINT8 *aux_ptr,
				   EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr)
{
	const UINT8 *kvBase = aux_ptr + auxHdr->KeyValuePairArrayOffset;
	UINT32 kvAvail =
		auxHdr->AuxiliaryDataSize - auxHdr->KeyValuePairArrayOffset;
	UINT32 kvNeeded = auxHdr->KeyValuePairArrayEntryCount *
			  sizeof(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR);
	if (kvNeeded > kvAvail) {
		return;
	}

	json_object *kvps = json_object_new_array();
	EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *kvArr =
		(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *)kvBase;
	for (UINT16 ki = 0; ki < auxHdr->KeyValuePairArrayEntryCount; ki++) {
		json_object *kv = json_object_new_object();
		EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *kvEntry = &kvArr[ki];
		EFI_GUID key = kvEntry->Key;
		add_guid(kv, "key", &key);

		json_object_object_add(kv, "value",
				       json_object_new_uint64(kvEntry->Value));
		if (is_mpam(&key)) {
			UINT16 partId = (UINT16)(kvEntry->Value & 0xFFFF);
			json_object_object_add(
				kv, "mpamPartId",
				json_object_new_uint64((UINT64)partId));
		}
		json_object_array_add(kvps, kv);
	}
	json_object_object_add(auxStructured, "keyValuePairs", kvps);
}

static json_object *arm_ras_parse_aux_data(const UINT8 *section, UINT32 size,
					   const EFI_ARM_RAS_NODE *node,
					   UINT64 descBytes)
{
	if (!node->AuxiliaryDataOffset) {
		return NULL;
	}

	const UINT8 *aux_ptr = section + node->AuxiliaryDataOffset;
	if (node->AuxiliaryDataOffset < sizeof(EFI_ARM_RAS_NODE) + descBytes) {
		cper_print_log("ARM RAS aux offset overlaps descriptors");
		return NULL;
	}

	UINT32 auxLen = size - node->AuxiliaryDataOffset;
	if (auxLen < sizeof(EFI_ARM_RAS_AUX_DATA_HEADER)) {
		cper_print_log("ARM RAS Auxiliary Data too small: %u < %zu",
			       auxLen, sizeof(EFI_ARM_RAS_AUX_DATA_HEADER));
		return NULL;
	}

	EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr =
		(EFI_ARM_RAS_AUX_DATA_HEADER *)aux_ptr;
	if (!arm_ras_aux_hdr_valid(auxHdr, auxLen)) {
		cper_print_log(
			"Invalid ARM RAS auxiliary header: version=%u, auxSize=%u, kvOffset=%u, kvCount=%u",
			auxHdr->Version, auxHdr->AuxiliaryDataSize,
			auxHdr->KeyValuePairArrayOffset,
			auxHdr->KeyValuePairArrayEntryCount);
		return NULL;
	}

	json_object *auxStructured = arm_ras_aux_emit_header_fields(auxHdr);
	if (!arm_ras_aux_parse_contexts(auxStructured, aux_ptr, auxHdr)) {
		return auxStructured;
	}
	arm_ras_aux_parse_kvps(auxStructured, aux_ptr, auxHdr);
	return auxStructured;
}

json_object *cper_section_arm_ras_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	EFI_ARM_RAS_NODE node;
	json_object *root = NULL;
	if (!arm_ras_read_node(&node, section, size, desc_string, &root)) {
		return root;
	}

	UINT32 descriptorCount = node.ErrorSyndromeArrayNumEntries;
	UINT64 descBytes = (UINT64)descriptorCount *
			   (UINT64)sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);

	arm_ras_set_desc_string_valid(desc_string);
	arm_ras_add_fixed_fields(root, &node);

	json_object *descArray =
		arm_ras_parse_descriptors(section, &node, descriptorCount);
	json_object_object_add(root, "errorSyndromes", descArray);

	json_object *auxStructured =
		arm_ras_parse_aux_data(section, size, &node, descBytes);

	if (auxStructured) {
		json_object_object_add(root, "auxData", auxStructured);
	}

	return root;
}

static void arm_ras_fill_node_fixed_fields(EFI_ARM_RAS_NODE *node,
					   json_object *section)
{
	json_object *obj = NULL;
	memset(node, 0, sizeof(*node));
	if (json_object_object_get_ex(section, "revision", &obj)) {
		node->Revision = (UINT32)json_object_get_uint64(obj);
	}
	if (json_object_object_get_ex(section, "componentType", &obj)) {
		node->ComponentType = (UINT8)json_object_get_int(obj);
	}
	if (json_object_object_get_ex(section, "ipInstanceFormat", &obj)) {
		node->IPInstanceFormat = (UINT8)json_object_get_int(obj);
	}
	if (json_object_object_get_ex(section, "ipTypeFormat", &obj)) {
		node->IPTypeFormat = (UINT8)json_object_get_int(obj);
	}
}

static void arm_ras_fill_node_identifiers(EFI_ARM_RAS_NODE *node,
					  json_object *section)
{
	json_object *t = NULL;
	if (json_object_object_get_ex(section, "ipInstance", &t)) {
		const char *hex = json_object_get_string(t);
		for (int i = 0;
		     i < ARM_RAS_IP_INSTANCE_BYTES &&
		     (int)strlen(hex) >= ARM_RAS_HEX_CHARS_PER_BYTE * (i + 1);
		     i++) {
			unsigned v;
			sscanf(&hex[i * 2], "%02x", &v);
			node->IPInstance[i] = (UINT8)v;
		}
	}
	if (json_object_object_get_ex(section, "ipType", &t)) {
		const char *hex = json_object_get_string(t);
		for (int i = 0;
		     i < ARM_RAS_IP_TYPE_BYTES &&
		     (int)strlen(hex) >= ARM_RAS_HEX_CHARS_PER_BYTE * (i + 1);
		     i++) {
			unsigned v;
			sscanf(&hex[i * 2], "%02x", &v);
			node->IPType[i] = (UINT8)v;
		}
	}
}

static void arm_ras_fill_node_user_data(EFI_ARM_RAS_NODE *node,
					json_object *section)
{
	json_object *t = NULL;
	if (json_object_object_get_ex(section, "userData", &t)) {
		const char *s = json_object_get_string(t);
		size_t l = strlen(s) > ARM_RAS_USER_DATA_MAX_JSON_CHARS ?
				   ARM_RAS_USER_DATA_MAX_JSON_CHARS :
				   strlen(s);
		memcpy(node->UserData, s, l);
		node->UserData[l] = 0;
	}
}

static void arm_ras_init_descriptor_metadata(EFI_ARM_RAS_NODE *node,
					     json_object *section,
					     json_object **descArr,
					     UINT32 *descCount,
					     UINT32 *afterDescriptors)
{
	*descArr = NULL;
	*descCount = 0;
	if (json_object_object_get_ex(section, "errorSyndromes", descArr)) {
		*descCount = json_object_array_length(*descArr);
	}
	if (*descCount > 896) {
		/*
		 * Per the RAS System Architecture (Arm IHI0100), the error_syndrome_array
		 * has at most 896 entries. Clamp larger inputs to avoid emitting
		 * non-architectural records.
		 */
		cper_print_log(
			"ARM RAS error_syndrome_array entry count too large: %u > 896; clamping to 0",
			(unsigned)*descCount);
		*descCount = 0;
	}
	/* Compute offsets */
	node->ErrorSyndromeArrayOffset = (UINT16)sizeof(EFI_ARM_RAS_NODE);
	*afterDescriptors =
		sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR) * (*descCount) +
		node->ErrorSyndromeArrayOffset;
}

static void arm_ras_build_aux_contexts(UINT8 *builtAux, UINT16 ctxCount,
				       json_object *contextsArr,
				       UINT32 headerSize)
{
	UINT8 *cursor = builtAux + headerSize;
	for (UINT16 ci = 0; ci < ctxCount; ci++) {
		json_object *ctx = json_object_array_get_idx(contextsArr, ci);
		if (!ctx) {
			continue;
		}
		json_object *regsArr = NULL;
		json_object_object_get_ex(ctx, "registers", &regsArr);
		UINT16 regCount =
			regsArr ? (UINT16)json_object_array_length(regsArr) : 0;
		UINT32 length = (UINT32)sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
				regCount * sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
		EFI_ARM_RAS_AUX_CONTEXT_HEADER *ch =
			(EFI_ARM_RAS_AUX_CONTEXT_HEADER *)cursor;
		ch->Length = length;
		json_object *flagsObj = NULL;
		json_object_object_get_ex(ctx, "flags", &flagsObj);
		ch->Flags = flagsObj ? (UINT8)json_object_get_int(flagsObj) : 0;
		ch->Reserved0 = 0;
		ch->RegisterArrayEntryCount = regCount;
		json_object *asidObj = NULL;
		json_object_object_get_ex(ctx, "addressSpaceIdentifier",
					  &asidObj);
		ch->AddressSpaceIdentifier =
			(asidObj && (ch->Flags & 0x1)) ?
				(UINT16)json_object_get_int(asidObj) :
				0;
		memset(ch->Reserved1, 0, sizeof(ch->Reserved1));
		EFI_ARM_RAS_AUX_MM_REG_ENTRY *regEntries =
			(EFI_ARM_RAS_AUX_MM_REG_ENTRY
				 *)(cursor +
				    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
		for (UINT16 ri = 0; ri < regCount; ri++) {
			json_object *r = json_object_array_get_idx(regsArr, ri);
			if (!r) {
				regEntries[ri].RegisterAddress = 0;
				regEntries[ri].RegisterValue = 0;
				continue;
			}
			json_object *addrObj = NULL;
			json_object *valObj = NULL;
			json_object_object_get_ex(r, "address", &addrObj);
			json_object_object_get_ex(r, "value", &valObj);
			regEntries[ri].RegisterAddress =
				addrObj ? json_object_get_uint64(addrObj) : 0;
			regEntries[ri].RegisterValue =
				valObj ? json_object_get_uint64(valObj) : 0;
		}
		cursor += length;
	}
}

static void arm_ras_build_aux_kvps(UINT8 *builtAux, UINT16 kvpCount,
				   json_object *kvpArr, UINT32 kvpOffset)
{
	EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *kvOut =
		(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *)(builtAux + kvpOffset);
	for (UINT16 ki = 0; ki < kvpCount; ki++) {
		json_object *kv = json_object_array_get_idx(kvpArr, ki);
		if (!kv) {
			memset(&kvOut[ki], 0, sizeof(kvOut[ki]));
			continue;
		}
		json_object *keyObj = NULL;
		json_object *valObj = NULL;
		json_object_object_get_ex(kv, "key", &keyObj);
		json_object_object_get_ex(kv, "value", &valObj);
		const char *hexKey = keyObj ? json_object_get_string(keyObj) :
					      NULL;
		string_to_guid(&kvOut[ki].Key, hexKey);

		kvOut[ki].Value = valObj ? json_object_get_uint64(valObj) : 0;
	}
}

static void arm_ras_build_aux_blob(json_object *auxStructured, UINT8 **builtAux,
				   UINT32 *builtAuxLen)
{
	*builtAux = NULL;
	*builtAuxLen = 0;
	if (!auxStructured) {
		return;
	}

	json_object *contextsArr = NULL;
	json_object_object_get_ex(auxStructured, "contexts", &contextsArr);
	json_object *kvpArr = NULL;
	json_object_object_get_ex(auxStructured, "keyValuePairs", &kvpArr);
	UINT16 ctxCount =
		contextsArr ? (UINT16)json_object_array_length(contextsArr) : 0;
	UINT16 kvpCount = kvpArr ? (UINT16)json_object_array_length(kvpArr) : 0;
	/* First compute size of contexts region */
	UINT32 contextsSize = 0;
	for (UINT16 i = 0; i < ctxCount; i++) {
		json_object *ctx = json_object_array_get_idx(contextsArr, i);
		if (!ctx) {
			continue;
		}
		json_object *regsArr = NULL;
		json_object_object_get_ex(ctx, "registers", &regsArr);
		UINT16 regCount =
			regsArr ? (UINT16)json_object_array_length(regsArr) : 0;
		UINT32 length = (UINT32)sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
				regCount * sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
		contextsSize += length;
	}
	UINT32 headerSize = sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
	UINT32 kvpOffset =
		headerSize + contextsSize; /* from start of aux block */
	UINT32 kvpSize = kvpCount * sizeof(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR);
	UINT32 auxSize = headerSize + contextsSize + kvpSize;

	/* Per the spec, AuxiliaryDataSize can be up to 2^32, but that's extreme and unrealistic.
	 * We limit auxSize to 0xFFFF to support reasonable sizes while keeping the code simple.
	 */
	if (auxSize > 0xFFFF) {
		cper_print_log(
			"Implementatoin doesn't support large AuxiliaryDataSize: %u > 0xFFFF",
			auxSize);
		return;
	}

	UINT8 *buf = (UINT8 *)calloc(1, auxSize);
	if (!buf) {
		return;
	}

	EFI_ARM_RAS_AUX_DATA_HEADER *hdr = (EFI_ARM_RAS_AUX_DATA_HEADER *)buf;
	hdr->Version = 1;
	hdr->Reserved0 = 0;
	hdr->AddressSpaceArrayEntryCount = ctxCount;
	hdr->AuxiliaryDataSize = auxSize;
	hdr->KeyValuePairArrayOffset = kvpOffset;
	hdr->KeyValuePairArrayEntryCount = kvpCount;
	hdr->Reserved1 = 0;

	/* Write contexts */
	arm_ras_build_aux_contexts(buf, ctxCount, contextsArr, headerSize);
	/* Write key-value pairs */
	arm_ras_build_aux_kvps(buf, kvpCount, kvpArr, kvpOffset);

	*builtAux = buf;
	*builtAuxLen = auxSize;
}

static void arm_ras_write_descriptors(json_object *descArr, UINT32 descCount,
				      FILE *out)
{
	for (UINT32 i = 0; i < descCount; i++) {
		EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR d;
		memset(&d, 0, sizeof(d));
		json_object *dj = json_object_array_get_idx(descArr, i);
		json_object *x = NULL;
		if (json_object_object_get_ex(dj, "errorRecordIndex", &x)) {
			d.ErrorRecordIndex = json_object_get_uint64(x);
		}
		/* Reconstruct rasExtensionRevision from split fields */
		UINT8 rev = 0;
		UINT8 arch = 0;
		if (json_object_object_get_ex(dj, "rasExtensionRevisionField",
					      &x)) {
			rev = (UINT8)json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "rasExtensionArchVer", &x)) {
			arch = (UINT8)json_object_get_uint64(x);
		}
		d.RasExtensionRevision = ((rev & 0x0F) << 4) | (arch & 0x0F);
		if (json_object_object_get_ex(dj, "errorRecordFeatureRegister",
					      &x)) {
			d.ERR_FR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordControlRegister",
					      &x)) {
			d.ERR_CTLR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(
			    dj, "errorRecordPrimaryStatusRegister", &x)) {
			d.ERR_STATUS = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordAddressRegister",
					      &x)) {
			d.ERR_ADDR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordMiscRegister0",
					      &x)) {
			d.ERR_MISC0 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordMiscRegister1",
					      &x)) {
			d.ERR_MISC1 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordMiscRegister2",
					      &x)) {
			d.ERR_MISC2 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errorRecordMiscRegister3",
					      &x)) {
			d.ERR_MISC3 = json_object_get_uint64(x);
		}
		fwrite(&d, sizeof(d), 1, out);
	}
}

void ir_section_arm_ras_to_cper(json_object *section, FILE *out)
{
	EFI_ARM_RAS_NODE node;
	arm_ras_fill_node_fixed_fields(&node, section);
	arm_ras_fill_node_identifiers(&node, section);
	arm_ras_fill_node_user_data(&node, section);

	json_object *descArr = NULL;
	UINT32 descCount = 0;
	UINT32 afterDescriptors = 0;
	arm_ras_init_descriptor_metadata(&node, section, &descArr, &descCount,
					 &afterDescriptors);

	json_object *auxStructured = NULL;
	json_object_object_get_ex(section, "auxData", &auxStructured);
	UINT8 *builtAux = NULL;
	UINT32 builtAuxLen = 0;
	arm_ras_build_aux_blob(auxStructured, &builtAux, &builtAuxLen);
	if (builtAux) {
		/*
		 * Architecturally safe: from the RAS System Architecture (Arm IHI0100),
		 * the header is 80 bytes and each ErrorSyndromes entry is 72 bytes,
		 * with at most 896 entries. So the maximum AuxiliaryDataOffset is
		 *   80 + 896 * 72 < 2^16,
		 * and fits in the UINT16 field.
		 */
		node.AuxiliaryDataOffset = (UINT16)afterDescriptors;
	} else {
		node.AuxiliaryDataOffset = 0;
	}
	node.ErrorSyndromeArrayNumEntries = descCount; // N

	fwrite(&node, sizeof(node), 1, out);
	arm_ras_write_descriptors(descArr, descCount, out);
	if (builtAux) {
		fwrite(builtAux, builtAuxLen, 1, out);
		free(builtAux);
	}
	fflush(out);
}
