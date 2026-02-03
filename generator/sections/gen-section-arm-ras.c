/**
 * Pseudo-random generator for ARM RAS CPER System Architecture Node (Revision 1).
 * Generates header (Table 20), error_syndrome_array entries (Table 21 descriptors),
 * and a structured auxiliary data block (Tables 22-26).
 * https://developer.arm.com/documentation/den0085/latest
 */

#include <stdlib.h>
#include <string.h>
#include <libcper/Cper.h>
#include <libcper/BaseTypes.h>
#include <libcper/generator/gen-utils.h>
#include <libcper/generator/sections/gen-section.h>
#include <stdbool.h>

/* Legacy component type retained as standalone field only */
#define ARM_RAS_COMPONENT_TYPE_MAX  0x6
#define ARM_RAS_RANDOM_USERDATA_LEN 15

/* IP_type_format enumeration per Table 20 */
enum {
	PE = 0,
	SMMU_IIDR,
	GIC_IIDR,
	PIDR,
	ARM_RAS_IP_TYPE_FORMAT_INVALID = 255
};

/* Auxiliary context generation metadata */
typedef struct {
	UINT16 regCount;
	UINT8 flags;
	UINT16 asid;
} GEN_CTX_META;

static bool gen_arm_ras_init_ctx_meta(GEN_CTX_META *ctxMeta, UINT16 ctxCount)
{
	for (UINT16 ci = 0; ci < ctxCount; ci++) {
		ctxMeta[ci].regCount =
			(UINT16)((cper_rand() % 4) + 1); /* 1..4 registers */
		ctxMeta[ci].flags = (UINT8)(cper_rand() & 0x1);
		ctxMeta[ci].asid = (ctxMeta[ci].flags & 0x1) ?
					   (UINT16)(cper_rand() & 0xFFFF) :
					   0;
	}
	return true;
}

static UINT32 gen_arm_ras_contexts_region_size(const GEN_CTX_META *ctxMeta,
					       UINT16 ctxCount)
{
	UINT32 contextsRegion = 0;
	for (UINT16 ci = 0; ci < ctxCount; ci++) {
		contextsRegion +=
			(UINT32)sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
			ctxMeta[ci].regCount *
				sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
	}
	return contextsRegion;
}

static bool gen_arm_ras_fill_node_fields(EFI_ARM_RAS_NODE *node,
					 UINT8 legacyType,
					 const UINT8 ipTypeFormatChoices[5])
{
	node->Revision = 1;
	/* Randomly select IPTypeFormat sometimes 255 (invalid/ignored => zero-filled IPType) */
	node->IPInstanceFormat = (UINT8)(cper_rand() % 4);
	node->IPTypeFormat = ipTypeFormatChoices[cper_rand() % 5];
	node->ComponentType = legacyType;
	memset(node->Reserved0, 0, sizeof(node->Reserved0));
	memset(node->Reserved1, 0, sizeof(node->Reserved1));

	UINT8 *tmp = generate_random_bytes(16);
	if (!tmp) {
		return false;
	}
	memcpy(node->IPInstance, tmp, 16);
	free(tmp);

	if (node->IPTypeFormat == ARM_RAS_IP_TYPE_FORMAT_INVALID) {
		memset(node->IPType, 0, 24);
	} else {
		tmp = generate_random_bytes(24);
		if (!tmp) {
			return false;
		}
		memcpy(node->IPType, tmp, 24);
		free(tmp);
	}

	char *udsrc =
		(char *)generate_random_bytes(ARM_RAS_RANDOM_USERDATA_LEN);
	if (!udsrc) {
		return false;
	}
	for (int i = 0; i < 15; i++) {
		char c = (char)('A' + (udsrc[i] % 26));
		node->UserData[i] = c;
	}
	node->UserData[15] = 0;
	free(udsrc);
	return true;
}

static void gen_arm_ras_fill_descriptors(UINT8 *buf, UINT16 offset,
					 UINT32 descriptorCount)
{
	UINT8 *cur = buf + offset;
	for (UINT32 i = 0; i < descriptorCount; i++) {
		EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR *d =
			(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR *)cur;
		memset(d, 0, sizeof(*d));
		d->ErrorRecordIndex = i;
		/* 25% chance of zero RasExtensionRevision (no MISC2/3) */
		if ((cper_rand() % 4) == 0) {
			d->RasExtensionRevision = 0;
		} else {
			UINT8 revHigh = (UINT8)(cper_rand() % 0x10);
			UINT8 revLow = (UINT8)(cper_rand() % 0x10);
			d->RasExtensionRevision = (revHigh << 4) | revLow;
		}
		d->ERR_FR = (UINT64)cper_rand();
		d->ERR_CTLR = (UINT64)cper_rand();
		d->ERR_STATUS = (UINT64)cper_rand();
		d->ERR_ADDR = (UINT64)cper_rand();
		d->ERR_MISC0 = (UINT64)cper_rand();
		d->ERR_MISC1 = (UINT64)cper_rand();
		if (d->RasExtensionRevision) {
			d->ERR_MISC2 = (UINT64)cper_rand();
			d->ERR_MISC3 = (UINT64)cper_rand();
		}
		cur += sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);
	}
}

static bool gen_arm_ras_fill_aux_data(UINT8 *buf, UINT16 auxOffset,
				      UINT32 chosenAuxLen, UINT16 ctxCount,
				      UINT16 kvCount, UINT32 contextsRegion,
				      const GEN_CTX_META *ctxMeta)
{
	UINT8 *auxBase = buf + auxOffset;
	EFI_ARM_RAS_AUX_DATA_HEADER *hdr =
		(EFI_ARM_RAS_AUX_DATA_HEADER *)auxBase;
	hdr->Version = 1;
	hdr->Reserved0 = 0;
	hdr->AddressSpaceArrayEntryCount = ctxCount;
	hdr->AuxiliaryDataSize = chosenAuxLen;
	UINT32 kvOffset =
		(UINT32)sizeof(EFI_ARM_RAS_AUX_DATA_HEADER) + contextsRegion;
	if (kvCount == 0) {
		kvOffset =
			hdr->AuxiliaryDataSize; /* zero-pair case per allowance */
	}
	hdr->KeyValuePairArrayOffset = kvOffset;
	hdr->KeyValuePairArrayEntryCount = kvCount;
	hdr->Reserved1 = 0;

	UINT8 *cursor = auxBase + sizeof(EFI_ARM_RAS_AUX_DATA_HEADER);
	/* Contexts */
	for (UINT16 ci = 0; ci < ctxCount; ci++) {
		UINT16 regCount = ctxMeta[ci].regCount;
		UINT32 ctxLen = (UINT32)sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER) +
				regCount * sizeof(EFI_ARM_RAS_AUX_MM_REG_ENTRY);
		EFI_ARM_RAS_AUX_CONTEXT_HEADER *ch =
			(EFI_ARM_RAS_AUX_CONTEXT_HEADER *)cursor;
		ch->Length = ctxLen;
		ch->Flags = ctxMeta[ci].flags;
		ch->Reserved0 = 0;
		ch->RegisterArrayEntryCount = regCount;
		ch->AddressSpaceIdentifier = ctxMeta[ci].asid;
		memset(ch->Reserved1, 0, sizeof(ch->Reserved1));
		EFI_ARM_RAS_AUX_MM_REG_ENTRY *regs =
			(EFI_ARM_RAS_AUX_MM_REG_ENTRY
				 *)(cursor +
				    sizeof(EFI_ARM_RAS_AUX_CONTEXT_HEADER));
		for (UINT16 r = 0; r < regCount; r++) {
			regs[r].RegisterAddress = (UINT64)cper_rand();
			regs[r].RegisterValue = (UINT64)cper_rand();
		}
		cursor += ctxLen;
	}

	/* Key-value pairs */
	if (kvCount) {
		EFI_ARM_RAS_AUX_KEY_VALUE_PAIR *kvOut =
			(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR
				 *)(auxBase + hdr->KeyValuePairArrayOffset);
		for (UINT16 ki = 0; ki < kvCount; ki++) {
			if ((cper_rand() % 4) == 0) {
				kvOut[ki].Key =
					EFI_ARM_RAS_KVP_UUID_MPAM_PARTID;
			} else {
				UINT8 *rb = generate_random_bytes(16);
				kvOut[ki].Key = *((EFI_GUID *)rb);
				free(rb);
			}
			kvOut[ki].Value = (UINT64)cper_rand();
		}
	}

	return true;
}

size_t generate_section_arm_ras(void **location,
				GEN_VALID_BITS_TEST_TYPE validBitsType)
{
	(void)validBitsType;

	/* Choose descriptor count and legacy component type (standalone only) */
	UINT32 descriptorCount = (cper_rand() % 4) + 1; // 1..4 descriptors
	UINT8 legacyType =
		(UINT8)(cper_rand() % (ARM_RAS_COMPONENT_TYPE_MAX + 1));

	/* Always generate structured auxiliary data per Tables 22-26 */
	UINT16 ctxCount = (UINT16)((cper_rand() % 3) + 1); /* 1..3 contexts */
	UINT16 kvCount = (UINT16)(cper_rand() % 4); /* 0..3 key-value pairs */
	/* Use enum values: 0..3 are valid formats, 255 is invalid */
	const UINT8 ipTypeFormatChoices[5] = { PE, SMMU_IIDR, GIC_IIDR, PIDR,
					       ARM_RAS_IP_TYPE_FORMAT_INVALID };
	/* Pre-determine each context's register count & metadata to keep sizes consistent */
	GEN_CTX_META *ctxMeta =
		(GEN_CTX_META *)calloc(ctxCount, sizeof(GEN_CTX_META));
	if (!ctxMeta) {
		return 0;
	}
	gen_arm_ras_init_ctx_meta(ctxMeta, ctxCount);

	UINT32 contextsRegion =
		gen_arm_ras_contexts_region_size(ctxMeta, ctxCount);
	UINT32 kvRegion = kvCount * sizeof(EFI_ARM_RAS_AUX_KEY_VALUE_PAIR);
	UINT32 chosenAuxLen = (UINT32)sizeof(EFI_ARM_RAS_AUX_DATA_HEADER) +
			      contextsRegion + kvRegion;

	size_t total =
		sizeof(EFI_ARM_RAS_NODE) +
		descriptorCount * sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR) +
		chosenAuxLen;

	UINT8 *buf = (UINT8 *)calloc(1, total);
	if (!buf) {
		free(ctxMeta);
		return 0;
	}
	EFI_ARM_RAS_NODE *node = (EFI_ARM_RAS_NODE *)buf;
	if (!gen_arm_ras_fill_node_fields(node, legacyType,
					  ipTypeFormatChoices)) {
		free(ctxMeta);
		free(buf);
		return 0;
	}

	node->ErrorSyndromeArrayOffset = (UINT16)sizeof(EFI_ARM_RAS_NODE);
	node->ErrorSyndromeArrayNumEntries = descriptorCount;
	UINT32 afterDescriptors =
		(UINT32)sizeof(EFI_ARM_RAS_NODE) +
		descriptorCount *
			(UINT32)sizeof(EFI_ARM_RAS_ERROR_RECORD_DESCRIPTOR);
	node->AuxiliaryDataOffset = chosenAuxLen ? (UINT16)afterDescriptors : 0;

	/* Populate descriptors */
	gen_arm_ras_fill_descriptors(buf, node->ErrorSyndromeArrayOffset,
				     descriptorCount);

	/* Auxiliary data generation */
	if (chosenAuxLen && node->AuxiliaryDataOffset) {
		if (!gen_arm_ras_fill_aux_data(buf, node->AuxiliaryDataOffset,
					       chosenAuxLen, ctxCount, kvCount,
					       contextsRegion, ctxMeta)) {
			free(ctxMeta);
			free(buf);
			return 0;
		}
	}

	free(ctxMeta);

	*location = buf;
	return total;
}
