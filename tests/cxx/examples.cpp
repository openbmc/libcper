/**
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * Compares the C++ (nlohmann::json) bindings output against the fixed golden
 * CPER examples (examples/<name>.cperhex) and their expected JSON
 * representations (examples/<name>.json), shared with tests/ir-tests.c.
 **/

#include "cper-example-sections.h"

#include <libcper.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

// The fixed CPER examples (binary + golden JSON) shared with tests/ir-tests.c.
constexpr std::array kExampleSections{CPER_EXAMPLE_SECTIONS};

// Returns the value of a single hex digit, or -1 if the character is not hex.
auto nibbleValue(char c) -> int
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

// Reads an examples/<name>.cperhex file (hex digits, whitespace ignored) into
// raw bytes.
auto loadBinary(const std::filesystem::path& path) -> std::vector<std::uint8_t>
{
    std::ifstream file(path);
    if (!file)
    {
        return {};
    }

    std::string hex(std::istreambuf_iterator<char>(file), {});

    std::vector<std::uint8_t> bytes;
    int high = -1;
    for (char c : hex)
    {
        if (std::isspace(static_cast<unsigned char>(c)))
        {
            continue;
        }
        int nibble = nibbleValue(c);
        if (nibble < 0)
        {
            return {};
        }
        if (high < 0)
        {
            high = nibble;
        }
        else
        {
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    if (high >= 0)
    {
        return {};
    }
    return bytes;
}

// Reads an examples/<name>.json file into a nlohmann::json value.
auto load(const std::filesystem::path& path) -> nlohmann::json
{
    std::ifstream file(path);
    return nlohmann::json::parse(file);
}

} // namespace

// Every fixed example binary must, when parsed through the C++ bindings,
// produce JSON structurally identical to the golden examples/<name>.json.
class ParseExamples : public ::testing::TestWithParam<const char*>
{};

TEST_P(ParseExamples, MatchesGoldenJson)
{
    std::string name = GetParam();

    std::vector<std::uint8_t> binary = loadBinary(
        std::filesystem::path(LIBCPER_EXAMPLES) / (name + ".cperhex"));
    ASSERT_FALSE(binary.empty());

    nlohmann::json expected =
        load(std::filesystem::path(LIBCPER_EXAMPLES) / (name + ".json"));

    nlohmann::json actual = libcper::ir::parseCPER(binary);
    ASSERT_FALSE(actual.is_null());

    EXPECT_EQ(actual, expected);
}

INSTANTIATE_TEST_SUITE_P(Golden, ParseExamples,
                         ::testing::ValuesIn(kExampleSections.begin(),
                                             kExampleSections.end()));
