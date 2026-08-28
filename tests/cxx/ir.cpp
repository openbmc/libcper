/**
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * Tests for the C++ (nlohmann::json) bindings.
 **/

#include <libcper/cper-parse-str.h>
#include <libcper/generator/cper-generate.h>

#include <libcper.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

namespace
{

constexpr GEN_VALID_BITS_TEST_TYPE kBits = ALL_VALID;

// Generates a CPER record (or single section) into a byte buffer.
auto generate(bool single_section) -> std::vector<std::uint8_t>
{
    char* buf = nullptr;
    size_t size = 0;
    FILE* stream = open_memstream(&buf, &size);
    if (stream == nullptr)
    {
        return {};
    }

    char type[] = "generic";
    if (single_section)
    {
        generate_single_section_record(type, stream, kBits);
    }
    else
    {
        char* types[] = {type};
        generate_cper_record(types, 1, stream, kBits);
    }
    fclose(stream);

    std::unique_ptr<char[], decltype(&std::free)> owned(buf, &std::free);
    return {owned.get(), owned.get() + size};
}

} // namespace

// The parsed IR of a generated record should have the expected shape.
TEST(ParseIr, FullRecordShape)
{
    std::vector<std::uint8_t> bytes = generate(false);
    ASSERT_FALSE(bytes.empty());

    nlohmann::json result = libcper::ir::parseCPER(bytes);
    ASSERT_FALSE(result.is_null());
    EXPECT_TRUE(result.contains("header"));
    EXPECT_TRUE(result.contains("sectionDescriptors"));
    EXPECT_TRUE(result.contains("sections"));
    EXPECT_EQ(result["header"]["sectionCount"], 1);
    EXPECT_EQ(result["sections"].size(), 1);
    EXPECT_NO_THROW(
        (void)result["header"]["severity"]["name"].get<std::string>());
}

// The IR parsed through the bindings should match the one produced by the
// native C string API.
TEST(ParseIr, MatchesCStringIr)
{
    std::vector<std::uint8_t> bytes = generate(false);
    ASSERT_FALSE(bytes.empty());

    nlohmann::json result = libcper::ir::parseCPER(bytes);
    ASSERT_FALSE(result.is_null());

    std::unique_ptr<char, decltype(&std::free)> str(
        cperbuf_to_str_ir(bytes.data(), bytes.size()), &std::free);
    ASSERT_NE(str.get(), nullptr);
    nlohmann::json cApi = nlohmann::json::parse(str.get());

    EXPECT_EQ(result, cApi);
}

// Invalid or truncated input must yield a null JSON value, mirroring the C
// API's NULL return value.
TEST(ParseIr, InvalidInputReturnsNull)
{
    std::vector<std::uint8_t> empty;
    EXPECT_TRUE(libcper::ir::parseCPER(empty).is_null());

    std::vector<std::uint8_t> truncated(64, 0xFF);
    EXPECT_TRUE(libcper::ir::parseCPER(truncated).is_null());
}

// A single section (with descriptor) should expose sectionDescriptor and the
// parsed section payload.
TEST(ParseIr, SingleSectionShape)
{
    std::vector<std::uint8_t> bytes = generate(true);
    ASSERT_FALSE(bytes.empty());

    nlohmann::json result = libcper::ir::parseCPERSection(bytes);
    ASSERT_FALSE(result.is_null());
    EXPECT_TRUE(result.contains("sectionDescriptor"));
    EXPECT_TRUE(result.contains("section"));
    EXPECT_NO_THROW((void)result["sectionDescriptor"]["severity"]["name"]
                        .get<std::string>());
}
