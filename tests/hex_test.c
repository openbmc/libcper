// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include <libcper/cper-utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <json.h>

// Test vectors: input bytes and expected hex strings
static const UINT8 test_bytes_1[] = { 0x00 };
static const char *test_hex_1 = "00";

static const UINT8 test_bytes_2[] = { 0xff };
static const char *test_hex_2 = "ff";

static const UINT8 test_bytes_3[] = { 0xde, 0xad, 0xbe, 0xef };
static const char *test_hex_3 = "deadbeef";

static const UINT8 test_bytes_4[] = { 0x01, 0x23, 0x45, 0x67,
				      0x89, 0xab, 0xcd, 0xef };
static const char *test_hex_4 = "0123456789abcdef";

static const UINT8 test_bytes_5[] = { 0x00, 0x00, 0x00, 0x00 };
static const char *test_hex_5 = "00000000";

// Test encoding: bytes -> hex string
void test_hex_encode_good(void)
{
	printf("Testing hex encoding...\n");

	// Test 1: Single zero byte
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_1, sizeof(test_bytes_1));
		json_object *field = json_object_object_get(obj, "data");
		assert(field != NULL);
		const char *hex = json_object_get_string(field);
		assert(strcmp(hex, test_hex_1) == 0);
		json_object_put(obj);
	}

	// Test 2: Single 0xFF byte
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_2, sizeof(test_bytes_2));
		json_object *field = json_object_object_get(obj, "data");
		assert(field != NULL);
		const char *hex = json_object_get_string(field);
		assert(strcmp(hex, test_hex_2) == 0);
		json_object_put(obj);
	}

	// Test 3: "deadbeef"
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_3, sizeof(test_bytes_3));
		json_object *field = json_object_object_get(obj, "data");
		assert(field != NULL);
		const char *hex = json_object_get_string(field);
		assert(strcmp(hex, test_hex_3) == 0);
		json_object_put(obj);
	}

	// Test 4: Full range 0-9, a-f
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_4, sizeof(test_bytes_4));
		json_object *field = json_object_object_get(obj, "data");
		assert(field != NULL);
		const char *hex = json_object_get_string(field);
		assert(strcmp(hex, test_hex_4) == 0);
		json_object_put(obj);
	}

	// Test 5: All zeros
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_5, sizeof(test_bytes_5));
		json_object *field = json_object_object_get(obj, "data");
		assert(field != NULL);
		const char *hex = json_object_get_string(field);
		assert(strcmp(hex, test_hex_5) == 0);
		json_object_put(obj);
	}

	printf("Hex encoding tests passed.\n");
}

// Test decoding: hex string -> bytes
void test_hex_decode_good(void)
{
	printf("Testing hex decoding...\n");

	// Test 1: Single zero byte
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", test_hex_1);
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes != NULL);
		assert(out_len == sizeof(test_bytes_1));
		assert(memcmp(bytes, test_bytes_1, out_len) == 0);
		free(bytes);
		json_object_put(obj);
	}

	// Test 2: Single 0xFF byte
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", test_hex_2);
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes != NULL);
		assert(out_len == sizeof(test_bytes_2));
		assert(memcmp(bytes, test_bytes_2, out_len) == 0);
		free(bytes);
		json_object_put(obj);
	}

	// Test 3: "deadbeef"
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", test_hex_3);
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes != NULL);
		assert(out_len == sizeof(test_bytes_3));
		assert(memcmp(bytes, test_bytes_3, out_len) == 0);
		free(bytes);
		json_object_put(obj);
	}

	// Test 4: Full range with uppercase hex
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "0123456789ABCDEF");
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes != NULL);
		assert(out_len == sizeof(test_bytes_4));
		assert(memcmp(bytes, test_bytes_4, out_len) == 0);
		free(bytes);
		json_object_put(obj);
	}

	// Test 5: Mixed case hex
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "DeAdBeEf");
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes != NULL);
		assert(out_len == sizeof(test_bytes_3));
		assert(memcmp(bytes, test_bytes_3, out_len) == 0);
		free(bytes);
		json_object_put(obj);
	}

	printf("Hex decoding tests passed.\n");
}

// Test error handling
void test_hex_error_cases(void)
{
	printf("Testing hex error handling...\n");

	// Test encode with NULL object
	{
		add_bytes_hex(NULL, "data", test_bytes_1, sizeof(test_bytes_1));
		// Should not crash
	}

	// Test encode with NULL bytes
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", NULL, 4);
		json_object *field = json_object_object_get(obj, "data");
		assert(field == NULL); // Should not add field
		json_object_put(obj);
	}

	// Test encode with zero length
	{
		json_object *obj = json_object_new_object();
		add_bytes_hex(obj, "data", test_bytes_1, 0);
		json_object *field = json_object_object_get(obj, "data");
		assert(field == NULL); // Should not add field
		json_object_put(obj);
	}

	// Test decode with NULL object
	{
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(NULL, "data", &out_len);
		assert(bytes == NULL);
	}

	// Test decode with NULL out_len
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "deadbeef");
		UINT8 *bytes = get_bytes_hex(obj, "data", NULL);
		assert(bytes == NULL);
		json_object_put(obj);
	}

	// Test decode with missing field
	{
		json_object *obj = json_object_new_object();
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "nonexistent", &out_len);
		assert(bytes == NULL);
		json_object_put(obj);
	}

	// Test decode with non-string field
	{
		json_object *obj = json_object_new_object();
		json_object_object_add(obj, "data", json_object_new_int(12345));
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes == NULL);
		json_object_put(obj);
	}

	// Test decode with odd-length hex string
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "abc");
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes == NULL); // Should fail - odd length
		json_object_put(obj);
	}

	// Test decode with invalid hex character
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "deadbXef");
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		assert(bytes == NULL); // Should fail - 'X' is invalid
		json_object_put(obj);
	}

	// Test decode with empty string
	{
		json_object *obj = json_object_new_object();
		add_string(obj, "data", "");
		size_t out_len = 0;
		UINT8 *bytes = get_bytes_hex(obj, "data", &out_len);
		// Empty string has even length (0), so it might succeed with 0 bytes
		// Or fail - depends on implementation. Current impl should return empty buf
		if (bytes != NULL) {
			assert(out_len == 0);
			free(bytes);
		}
		json_object_put(obj);
	}

	printf("Hex error handling tests passed.\n");
}

// Test round-trip: bytes -> hex -> bytes
void test_hex_roundtrip(void)
{
	printf("Testing hex round-trip...\n");

	// Test with various byte patterns
	UINT8 test_data[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	json_object *obj = json_object_new_object();
	add_bytes_hex(obj, "roundtrip", test_data, sizeof(test_data));

	size_t out_len = 0;
	UINT8 *decoded = get_bytes_hex(obj, "roundtrip", &out_len);
	assert(decoded != NULL);
	assert(out_len == sizeof(test_data));
	assert(memcmp(decoded, test_data, out_len) == 0);

	free(decoded);
	json_object_put(obj);

	printf("Hex round-trip tests passed.\n");
}
