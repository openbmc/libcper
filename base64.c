#include <libcper/base64.h>
#include <libcper/BaseTypes.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const UINT8 encode_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 *
 * Caller is responsible for freeing the returned buffer.
 */
CHAR8 *base64_encode(const UINT8 *src, INT32 len, INT32 *out_len)
{
	CHAR8 *out;
	CHAR8 *out_pos;
	const UINT8 *src_end;
	const UINT8 *in_pos;

	if (len <= 0) {
		return NULL;
	}

	if (!out_len) {
		return NULL;
	}

	// 3 byte blocks to 4 byte blocks plus up to 2 bytes of padding
	*out_len = 4 * ((len + 2) / 3);

	// Handle overflows
	if (*out_len < len) {
		return NULL;
	}

	out = malloc(*out_len);
	if (out == NULL) {
		return NULL;
	}

	src_end = src + len;
	in_pos = src;
	out_pos = out;
	while (src_end - in_pos >= 3) {
		*out_pos++ = encode_table[in_pos[0] >> 2];
		*out_pos++ = encode_table[((in_pos[0] & 0x03) << 4) |
					  (in_pos[1] >> 4)];
		*out_pos++ = encode_table[((in_pos[1] & 0x0f) << 2) |
					  (in_pos[2] >> 6)];
		*out_pos++ = encode_table[in_pos[2] & 0x3f];
		in_pos += 3;
	}

	if (src_end - in_pos) {
		*out_pos++ = encode_table[in_pos[0] >> 2];
		if (src_end - in_pos == 1) {
			*out_pos++ = encode_table[(in_pos[0] & 0x03) << 4];
			*out_pos++ = '=';
		} else {
			*out_pos++ = encode_table[((in_pos[0] & 0x03) << 4) |
						  (in_pos[1] >> 4)];
			*out_pos++ = encode_table[(in_pos[1] & 0x0f) << 2];
		}
		*out_pos++ = '=';
	}

	return out;
}

// Base64 decode table.  Invalid values are specified with 0x80.
UINT8 decode_table[256] __attribute__((nonstring)) =
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x3e\x80\x80\x80\x3f"
	"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x80\x80\x80\x00\x80\x80"
	"\x80\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
	"\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x80\x80\x80\x80\x80"
	"\x80\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28"
	"\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
	"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80";

/**
 *
 * Caller is responsible for freeing the returned buffer.
 */
UINT8 *base64_decode(const CHAR8 *src, INT32 len, INT32 *out_len)
{
	UINT8 *out = NULL;
	UINT8 *pos = NULL;
	UINT8 block[4];
	INT32 block_index = 0;
	INT32 src_index = 0;

	if (!out_len) {
		goto error;
	}

	// Malloc might be up to 2 larger dependent on padding
	*out_len = len / 4 * 3 + 2;
	pos = out = malloc(*out_len);
	if (out == NULL) {
		goto error;
	}

	block_index = 0;
	for (src_index = 0; src_index < len; src_index++) {
		char current_char = src[src_index];
		if (current_char == '=') {
			break;
		}
		// If the final character is a newline, as can occur in many editors
		// then ignore it.
		if (src_index + 1 == len && current_char == '\n') {
			printf("Ignoring trailing newline.\n");
			break;
		}

		block[block_index] = decode_table[(UINT8)current_char];
		if (block[block_index] == 0x80) {
			printf("Invalid character \"%c\".\n", current_char);
			goto error;
		}

		block_index++;
		if (block_index == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			block_index = 0;
		}
	}
	if (block_index == 0) {
		// mod 4 Even number of characters, no padding.
	} else if (block_index == 1) {
		printf("Invalid base64 input length.  Last character truncated.\n");
		goto error;
	} else if (block_index == 2) {
		*pos++ = (block[0] << 2) | (block[1] >> 4);
	} else if (block_index == 3) {
		*pos++ = (block[0] << 2) | (block[1] >> 4);
		*pos++ = (block[1] << 4) | (block[2] >> 2);
	} else {
		/* Invalid pad_counting */
		printf("Invalid base64 input length %d.\n", block_index);
		goto error;
	}

	*out_len = pos - out;
	return out;

error:
	free(out);
	return NULL;
}
