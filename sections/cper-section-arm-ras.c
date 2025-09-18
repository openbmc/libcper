/**
 * See: https://developer.arm.com/documentation/den0085/latest/
 * Minimal parser/generator for ARM RAS CPER section (Table 20/21)
 * Author: prachotan.bathi@arm.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <json.h>
#include <inttypes.h>
#include <libcper/Cper.h>
#include <libcper/base64.h>
#include <libcper/sections/cper-section-arm.h>
#include <libcper/log.h>

json_object *cper_section_arm_ras_to_ir(const UINT8 *section, UINT32 size,
					char **desc_string)
{
	if (size < sizeof(EFI_ARM_RAS_NODE)) {
		cper_print_log("ARM RAS section too small: %u < %zu",
			       (unsigned)size, sizeof(EFI_ARM_RAS_NODE));
		return NULL;
	}
	EFI_ARM_RAS_NODE node;
	memcpy(&node, section, sizeof(node));
	if (node.Revision != 1) {
		cper_print_log("Unsupported ARM RAS revision: %u",
			       node.Revision);
		return NULL;
	}

	if (node.ErrorSyndromeArrayOffset < sizeof(EFI_ARM_RAS_NODE) ||
	    node.ErrorSyndromeArrayOffset >= size ||
	    (node.AuxiliaryDataOffset && node.AuxiliaryDataOffset >= size)) {
		cper_print_log("Invalid ARM RAS offsets");
		return NULL;
	}

	UINT32 descriptorCount = node.ErrorSyndromeArrayNumEntries;
	const UINT8 *desc_ptr = section + node.ErrorSyndromeArrayOffset;
	const UINT8 *aux_ptr = (node.AuxiliaryDataOffset) ?
				       section + node.AuxiliaryDataOffset :
				       NULL;

	json_object *root = json_object_new_object();
	*desc_string = malloc(SECTION_DESC_STRING_SIZE);
	snprintf(*desc_string, SECTION_DESC_STRING_SIZE,
		 "ARM RAS (rev %u) legacyType %u, %u entries", node.Revision,
		 node.ComponentType, descriptorCount);

	json_object_object_add(root, "revision",
			       json_object_new_uint64(node.Revision));
	json_object_object_add(root, "componentType",
			       json_object_new_int(node.ComponentType));
	json_object_object_add(
		root, "errorSyndromeArrayOffset",
		json_object_new_int(node.ErrorSyndromeArrayOffset));
	json_object_object_add(root, "auxDataOffset",
			       json_object_new_int(node.AuxiliaryDataOffset));
	json_object_object_add(
		root, "errorSyndromeArrayNumEntries",
		json_object_new_int(node.ErrorSyndromeArrayNumEntries));
	json_object_object_add(root, "ipInstanceFormat",
			       json_object_new_int(node.IPInstanceFormat));
	json_object_object_add(root, "ipTypeFormat",
			       json_object_new_int(node.IPTypeFormat));

	char hexBuf[2 * 24 + 1];
	for (int i = 0; i < 16; i++) {
		sprintf(&hexBuf[i * 2], "%02x", node.IPInstance[i]);
	}
	json_object_object_add(root, "ipInstance",
			       json_object_new_string_len(hexBuf, 32));
	for (int i = 0; i < 24; i++) {
		sprintf(&hexBuf[i * 2], "%02x", node.IPType[i]);
	}
	json_object_object_add(root, "ipType",
			       json_object_new_string_len(hexBuf, 48));

	int udLen = 0;
	for (; udLen < 16 && node.UserData[udLen] != 0; udLen++) {
		;
	}
	if (udLen == 16) {
		udLen = 15;
	}
	json_object_object_add(
		root, "userData",
		json_object_new_string_len((const char *)node.UserData, udLen));

	json_object *descArray = json_object_new_array();
	for (UINT32 i = 0; i < descriptorCount; i++) {
		const UINT8 *cur =
			desc_ptr +
			i * sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);
		if (cur + sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR) >
		    section + size) {
			break;
		}
		EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR d;
		memcpy(&d, cur, sizeof(d));
		json_object *jd = json_object_new_object();
		json_object_object_add(
			jd, "errorRecordIndex",
			json_object_new_uint64(d.ErrorRecordIndex));
		json_object_object_add(
			jd, "rasExtensionRevision",
			json_object_new_uint64(d.RasExtensionRevision));
		json_object_object_add(jd, "errFR",
				       json_object_new_uint64(d.ERR_FR));
		json_object_object_add(jd, "errCTLR",
				       json_object_new_uint64(d.ERR_CTLR));
		json_object_object_add(jd, "errSTATUS",
				       json_object_new_uint64(d.ERR_STATUS));
		json_object_object_add(jd, "errADDR",
				       json_object_new_uint64(d.ERR_ADDR));
		json_object_object_add(jd, "errMISC0",
				       json_object_new_uint64(d.ERR_MISC0));
		json_object_object_add(jd, "errMISC1",
				       json_object_new_uint64(d.ERR_MISC1));
		if (d.RasExtensionRevision) {
			json_object_object_add(
				jd, "errMISC2",
				json_object_new_uint64(d.ERR_MISC2));
			json_object_object_add(
				jd, "errMISC3",
				json_object_new_uint64(d.ERR_MISC3));
		}
		json_object_array_add(descArray, jd);
	}
	json_object_object_add(root, "errorSyndromeArray", descArray);

	if (aux_ptr) {
		UINT32 auxLen = size - node.AuxiliaryDataOffset;
		if (auxLen >= sizeof(EFI_ARM_RAS_AUX_DATA_HEADER)) {
			const EFI_ARM_RAS_AUX_DATA_HEADER *auxHdr =
				(const EFI_ARM_RAS_AUX_DATA_HEADER *)aux_ptr;
			bool kvOffsetValid =
				((auxHdr->KeyValuePairArrayEntryCount == 0 &&
				  auxHdr->KeyValuePairArrayOffset ==
					  auxHdr->AuxiliaryDataSize) ||
				 (auxHdr->KeyValuePairArrayOffset <
				  auxHdr->AuxiliaryDataSize));
			bool hdrValid = (auxHdr->Version == 1) &&
					(auxHdr->Reserved0 == 0) &&
					(auxHdr->Reserved1 == 0) &&
					(auxHdr->AuxiliaryDataSize <= auxLen) &&
					(auxHdr->AuxiliaryDataSize >=
					 sizeof(EFI_ARM_RAS_AUX_DATA_HEADER)) &&
					kvOffsetValid &&
					(auxHdr->KeyValuePairArrayOffset >=
					 sizeof(EFI_ARM_RAS_AUX_DATA_HEADER));
			if (hdrValid) {
				/* Emit auxiliary header fields in spec order (Table 22):
				 * version, reserved0 (omitted - always zero), addressSpaceArrayEntryCount,
				 * auxiliaryDataSize, keyValuePairArrayOffset, keyValuePairArrayEntryCount, reserved1 (omitted).
				 */
				json_object *auxStructured =
					json_object_new_object();
				json_object_object_add(
					auxStructured, "version",
					json_object_new_int(auxHdr->Version));
				json_object_object_add(
					auxStructured,
					"addressSpaceArrayEntryCount",
					json_object_new_int(
						auxHdr->AddressSpaceArrayEntryCount));
				json_object_object_add(
					auxStructured, "auxiliaryDataSize",
					json_object_new_int(
						(int)auxHdr->AuxiliaryDataSize));
				json_object_object_add(
					auxStructured,
					"keyValuePairArrayOffset",
					json_object_new_int(
						(int)auxHdr
							->KeyValuePairArrayOffset));
				json_object_object_add(
					auxStructured,
					"keyValuePairArrayEntryCount",
					json_object_new_int(
						auxHdr->KeyValuePairArrayEntryCount));
				json_object *contexts = json_object_new_array();
				const UINT8 *cursor =
					aux_ptr +
					sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
				UINT32 remaining =
					auxHdr->AuxiliaryDataSize -
					sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
				bool ok = true;
				for (UINT16 ci = 0;
				     ci < auxHdr->AddressSpaceArrayEntryCount;
				     ci++) {
					if (remaining <
					    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER)) {
						ok = false;
						break;
					}
					const EFI_ARM_RAS_AUX_CONTEXT_HEADER *ctx =
						(const EFI_ARM_RAS_AUX_CONTEXT_HEADER
							 *)cursor;
					if (ctx->Length <
					    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER)) {
						ok = false;
						break;
					}
					UINT32 needed =
						sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
						ctx->RegisterArrayEntryCount *
							sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
					if (ctx->Length < needed ||
					    needed > remaining) {
						ok = false;
						break;
					}
					UINT32 afterCtxOffset =
						(UINT32)(cursor - aux_ptr) +
						ctx->Length;
					if (afterCtxOffset >
					    auxHdr->KeyValuePairArrayOffset) {
						ok = false;
						break;
					}
					json_object *ctxObjInstance =
						json_object_new_object();
					json_object_object_add(
						ctxObjInstance, "length",
						json_object_new_int(
							(int)ctx->Length));
					json_object_object_add(
						ctxObjInstance, "flags",
						json_object_new_int(
							(int)ctx->Flags));
					json_object_object_add(
						ctxObjInstance,
						"registerArrayEntryCount",
						json_object_new_int(
							(int)ctx->RegisterArrayEntryCount));
					if (ctx->Flags & 0x1) {
						json_object_object_add(
							ctxObjInstance,
							"addressSpaceIdentifier",
							json_object_new_int(
								(int)ctx->AddressSpaceIdentifier));
					}
					json_object *regs =
						json_object_new_array();
					const EFI_ARM_RAS_AUX_MM_REG_ENTRY *regArr =
						(const EFI_ARM_RAS_AUX_MM_REG_ENTRY
							 *)(cursor +
							    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
					for (UINT16 ri = 0;
					     ri < ctx->RegisterArrayEntryCount;
					     ri++) {
						json_object *r =
							json_object_new_object();
						json_object_object_add(
							r, "address",
							json_object_new_uint64(
								regArr[ri]
									.RegisterAddress));
						json_object_object_add(
							r, "value",
							json_object_new_uint64(
								regArr[ri]
									.RegisterValue));
						json_object_array_add(regs, r);
					}
					json_object_object_add(ctxObjInstance,
							       "registers",
							       regs);
					json_object_array_add(contexts,
							      ctxObjInstance);
					cursor += ctx->Length;
					remaining -= ctx->Length;
				}
				if (ok) {
					json_object_object_add(auxStructured,
							       "contexts",
							       contexts);
					const UINT8 *kvBase =
						aux_ptr +
						auxHdr->KeyValuePairArrayOffset;
					UINT32 kvAvail =
						auxHdr->AuxiliaryDataSize -
						auxHdr->KeyValuePairArrayOffset;
					UINT32 kvNeeded =
						auxHdr->KeyValuePairArrayEntryCount *
						sizeof(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR);
					if (kvNeeded <= kvAvail) {
						json_object *kvps =
							json_object_new_array();
						const EFI_ARM_RAS_AUX_KEY_VALUE_PAIR
							*kvArr =
								(const EFI_ARM_RAS_AUX_KEY_VALUE_PAIR
									 *)
									kvBase;
						for (UINT16 ki = 0;
						     ki <
						     auxHdr->KeyValuePairArrayEntryCount;
						     ki++) {
							json_object *kv =
								json_object_new_object();
							char uuidStr[37];
							const UINT8 *kb =
								kvArr[ki].Key;
							snprintf(
								uuidStr,
								sizeof(uuidStr),
								"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
								kb[0], kb[1],
								kb[2], kb[3],
								kb[4], kb[5],
								kb[6], kb[7],
								kb[8], kb[9],
								kb[10], kb[11],
								kb[12], kb[13],
								kb[14], kb[15]);
							json_object_object_add(
								kv, "key",
								json_object_new_string(
									uuidStr));
							json_object_object_add(
								kv, "value",
								json_object_new_uint64(
									kvArr[ki]
										.Value));
							if (memcmp(kvArr[ki].Key,
								   EFI_ARM_RAS_KVP_UUID_MPAM_PARTID,
								   16) == 0) {
								UINT16 partId =
									(UINT16)(kvArr[ki]
											 .Value &
										 0xFFFF);
								json_object_object_add(
									kv,
									"mpamPartId",
									json_object_new_int(
										partId));
							}
							json_object_array_add(
								kvps, kv);
						}
						json_object_object_add(
							auxStructured,
							"keyValuePairs", kvps);
					}
				}
				json_object_object_add(root,
						       "auxDataStructured",
						       auxStructured);
			}
		}
	}

	return root;
}

void ir_section_arm_ras_to_cper(json_object *section, FILE *out)
{
	EFI_ARM_RAS_NODE node;
	memset(&node, 0, sizeof(node));
	json_object *obj = NULL;
	if (json_object_object_get_ex(section, "revision", &obj)) {
		node.Revision = (UINT32)json_object_get_uint64(obj);
	}
	if (json_object_object_get_ex(section, "componentType", &obj)) {
		node.ComponentType = (UINT8)json_object_get_int(obj);
	}
	if (json_object_object_get_ex(section, "ipInstanceFormat", &obj)) {
		node.IPInstanceFormat = (UINT8)json_object_get_int(obj);
	}
	if (json_object_object_get_ex(section, "ipTypeFormat", &obj)) {
		node.IPTypeFormat = (UINT8)json_object_get_int(obj);
	}

	json_object *t = NULL;
	if (json_object_object_get_ex(section, "ipInstance", &t)) {
		const char *hex = json_object_get_string(t);
		for (int i = 0; i < 16 && (int)strlen(hex) >= 2 * (i + 1);
		     i++) {
			unsigned v;
			sscanf(&hex[i * 2], "%02x", &v);
			node.IPInstance[i] = (UINT8)v;
		}
	}
	if (json_object_object_get_ex(section, "ipType", &t)) {
		const char *hex = json_object_get_string(t);
		for (int i = 0; i < 24 && (int)strlen(hex) >= 2 * (i + 1);
		     i++) {
			unsigned v;
			sscanf(&hex[i * 2], "%02x", &v);
			node.IPType[i] = (UINT8)v;
		}
	}
	if (json_object_object_get_ex(section, "userData", &t)) {
		const char *s = json_object_get_string(t);
		size_t l = strlen(s) > 15 ? 15 : strlen(s);
		memcpy(node.UserData, s, l);
		node.UserData[l] = 0;
	}

	json_object *descArr = NULL;
	UINT32 descCount = 0;
	if (json_object_object_get_ex(section, "errorSyndromeArray",
				      &descArr)) {
		descCount = json_object_array_length(descArr);
	}
	json_object *auxStructured = NULL;
	json_object_object_get_ex(section, "auxDataStructured", &auxStructured);

	// Compute offsets
	node.ErrorSyndromeArrayOffset = (UINT16)sizeof(EFI_ARM_RAS_NODE);
	UINT32 afterDescriptors =
		sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR) * descCount +
		node.ErrorSyndromeArrayOffset;
	/* Build auxiliary data if structured object provided */
	UINT8 *builtAux = NULL;
	UINT32 builtAuxLen = 0;
	if (auxStructured) {
		/* Build structured auxiliary data blob */
		json_object *contextsArr = NULL;
		json_object_object_get_ex(auxStructured, "contexts",
					  &contextsArr);
		json_object *kvpArr = NULL;
		json_object_object_get_ex(auxStructured, "keyValuePairs",
					  &kvpArr);
		UINT16 ctxCount =
			contextsArr ?
				(UINT16)json_object_array_length(contextsArr) :
				0;
		UINT16 kvpCount =
			kvpArr ? (UINT16)json_object_array_length(kvpArr) : 0;
		/* First compute size of contexts region */
		UINT32 contextsSize = 0;
		for (UINT16 i = 0; i < ctxCount; i++) {
			json_object *ctx =
				json_object_array_get_idx(contextsArr, i);
			if (!ctx) {
				continue;
			}
			json_object *flagsObj = NULL;
			json_object_object_get_ex(ctx, "flags", &flagsObj);
			json_object *regsArr = NULL;
			json_object_object_get_ex(ctx, "registers", &regsArr);
			UINT16 regCount =
				regsArr ? (UINT16)json_object_array_length(
						  regsArr) :
					  0;
			UINT32 length =
				(UINT32)sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
				regCount * sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
			contextsSize += length;
		}
		UINT32 headerSize = sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
		UINT32 kvpOffset =
			headerSize + contextsSize; /* from start of aux block */
		UINT32 kvpSize =
			kvpCount * sizeof(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR);
		UINT32 auxSize = headerSize + contextsSize + kvpSize;
		if (auxSize && auxSize <= 0xFFFF) {
			builtAux = (UINT8 *)calloc(1, auxSize);
			if (builtAux) {
				EFI_ARM_RAS_AUX_DATA_HEADER *hdr =
					(EFI_ARM_RAS_AUX_DATA_HEADER *)builtAux;
				hdr->Version = 1;
				hdr->Reserved0 = 0;
				hdr->AddressSpaceArrayEntryCount = ctxCount;
				hdr->AuxiliaryDataSize = auxSize;
				hdr->KeyValuePairArrayOffset = kvpOffset;
				hdr->KeyValuePairArrayEntryCount = kvpCount;
				hdr->Reserved1 = 0;
				/* Write contexts */
				UINT8 *cursor = builtAux + headerSize;
				for (UINT16 ci = 0; ci < ctxCount; ci++) {
					json_object *ctx =
						json_object_array_get_idx(
							contextsArr, ci);
					if (!ctx) {
						continue;
					}
					json_object *regsArr = NULL;
					json_object_object_get_ex(
						ctx, "registers", &regsArr);
					UINT16 regCount =
						regsArr ?
							(UINT16)json_object_array_length(
								regsArr) :
							0;
					UINT32 length =
						(UINT32)sizeof(
							EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
						regCount *
							sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
					EFI_ARM_RAS_AUX_CONTEXT_HEADER *ch =
						(EFI_ARM_RAS_AUX_CONTEXT_HEADER
							 *)cursor;
					ch->Length = length;
					json_object *flagsObj = NULL;
					json_object_object_get_ex(ctx, "flags",
								  &flagsObj);
					ch->Flags =
						flagsObj ?
							(UINT8)json_object_get_int(
								flagsObj) :
							0;
					ch->Reserved0 = 0;
					ch->RegisterArrayEntryCount = regCount;
					json_object *asidObj = NULL;
					json_object_object_get_ex(
						ctx, "addressSpaceIdentifier",
						&asidObj);
					ch->AddressSpaceIdentifier =
						(asidObj && (ch->Flags & 0x1)) ?
							(UINT16)json_object_get_int(
								asidObj) :
							0;
					memset(ch->Reserved1, 0,
					       sizeof(ch->Reserved1));
					EFI_ARM_RAS_AUX_MM_REG_ENTRY *regEntries =
						(EFI_ARM_RAS_AUX_MM_REG_ENTRY
							 *)(cursor +
							    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
					for (UINT16 ri = 0; ri < regCount;
					     ri++) {
						json_object *r =
							json_object_array_get_idx(
								regsArr, ri);
						if (!r) {
							regEntries[ri]
								.RegisterAddress =
								0;
							regEntries[ri]
								.RegisterValue =
								0;
							continue;
						}
						json_object *addrObj = NULL;
						json_object *valObj = NULL;
						json_object_object_get_ex(
							r, "address", &addrObj);
						json_object_object_get_ex(
							r, "value", &valObj);
						regEntries[ri].RegisterAddress =
							addrObj ?
								json_object_get_uint64(
									addrObj) :
								0;
						regEntries[ri].RegisterValue =
							valObj ?
								json_object_get_uint64(
									valObj) :
								0;
					}
					cursor += length;
				}
				/* Write key-value pairs */
				EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *kvOut =
					(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR
						 *)(builtAux + kvpOffset);
				for (UINT16 ki = 0; ki < kvpCount; ki++) {
					json_object *kv =
						json_object_array_get_idx(
							kvpArr, ki);
					if (!kv) {
						memset(&kvOut[ki], 0,
						       sizeof(kvOut[ki]));
						continue;
					}
					json_object *keyObj = NULL;
					json_object *valObj = NULL;
					json_object_object_get_ex(kv, "uuid",
								  &keyObj);
					if (!keyObj) {
						json_object_object_get_ex(
							kv, "key", &keyObj);
					}
					json_object_object_get_ex(kv, "value",
								  &valObj);
					const char *hexKey =
						keyObj ? json_object_get_string(
								 keyObj) :
							 NULL;
					if (hexKey && strlen(hexKey) >= 32) {
						for (int bi = 0; bi < 16;
						     bi++) {
							unsigned v = 0;
							sscanf(&hexKey[bi * 2],
							       "%02x", &v);
							kvOut[ki].Key[bi] =
								(UINT8)v;
						}
					} else {
						memset(kvOut[ki].Key, 0, 16);
					}
					kvOut[ki].Value =
						valObj ? json_object_get_uint64(
								 valObj) :
							 0;
				}
				builtAuxLen = auxSize;
			}
		}
	}
	if (builtAux) {
		node.AuxiliaryDataOffset = (UINT16)afterDescriptors;
	} else {
		node.AuxiliaryDataOffset = 0;
	}
	node.ErrorSyndromeArrayNumEntries = descCount; // N

	fwrite(&node, sizeof(node), 1, out);
	// Emit descriptors
	for (UINT32 i = 0; i < descCount; i++) {
		EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR d;
		memset(&d, 0, sizeof(d));
		json_object *dj = json_object_array_get_idx(descArr, i);
		json_object *x = NULL;
		if (json_object_object_get_ex(dj, "errorRecordIndex", &x)) {
			d.ErrorRecordIndex = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "rasExtensionRevision", &x)) {
			d.RasExtensionRevision = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errFR", &x)) {
			d.ERR_FR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errCTLR", &x)) {
			d.ERR_CTLR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errSTATUS", &x)) {
			d.ERR_STATUS = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errADDR", &x)) {
			d.ERR_ADDR = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errMISC0", &x)) {
			d.ERR_MISC0 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errMISC1", &x)) {
			d.ERR_MISC1 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errMISC2", &x)) {
			d.ERR_MISC2 = json_object_get_uint64(x);
		}
		if (json_object_object_get_ex(dj, "errMISC3", &x)) {
			d.ERR_MISC3 = json_object_get_uint64(x);
		}
		fwrite(&d, sizeof(d), 1, out);
	}
	if (builtAux) {
		fwrite(builtAux, builtAuxLen, 1, out);
		free(builtAux);
	}
	fflush(out);
}
