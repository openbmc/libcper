#include "base64.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

TEST(Base64Encode, Good)
{
	int32_t encoded_len = 0;
	std::array<uint8_t, 1> data = { 'f' };
	char *encoded = base64_encode(data.data(), data.size(), &encoded_len);
	EXPECT_EQ(encoded_len, 4);
	ASSERT_EQ(std::string_view(encoded, encoded_len), "Zg==");
	free(encoded);
}

TEST(Base64Decode, Good)
{
	int32_t decoded_len = 0;
	std::string_view data{ "Zg==" };
	UINT8 *decoded = base64_decode(data.data(), data.size(), &decoded_len);
	EXPECT_EQ(decoded_len, 1);
	ASSERT_EQ(decoded[0], 'f');
	free(decoded);
}
