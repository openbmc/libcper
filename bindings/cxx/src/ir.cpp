/**
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright OpenBMC Authors
 *
 * C++ (nlohmann::json) bindings for libcper.
 *
 * These functions parse CPER records using the existing json-c based C
 * parser and expose the result as nlohmann::json. Parsing the serialized
 * json-c string guarantees the output is byte-identical to the IR produced
 * by the native C library, since json-c remains the single source of truth.
 **/

#include <json.h>
#include <libcper/cper-parse.h>

#include <libcper.hpp>

#include <cstdint>
#include <exception>
#include <memory>
#include <span>

namespace libcper
{

namespace
{

// Releases a json-c object with json_object_put() on destruction, so the C
// allocation is freed even if the IR conversion below throws.
struct JsonObjectDeleter
{
    void operator()(json_object* obj) const noexcept
    {
        json_object_put(obj);
    }
};

using JsonObjectPtr = std::unique_ptr<json_object, JsonObjectDeleter>;

// Converts a json-c IR object to nlohmann::json. Does not take ownership;
// callers must keep the json_object alive for the duration of the call.
auto irToJson(json_object* ir) -> nlohmann::json
{
    if (ir == nullptr)
    {
        return nullptr;
    }

    try
    {
        return nlohmann::json::parse(json_object_to_json_string(ir));
    }
    catch (const std::exception&)
    {
        return nullptr;
    }
}

} // namespace

namespace ir
{

auto parseCPER(std::span<const std::uint8_t> cperData) -> nlohmann::json
{
    JsonObjectPtr ir(
        cper_buf_to_ir(reinterpret_cast<const unsigned char*>(cperData.data()),
                       cperData.size()));
    return irToJson(ir.get());
}

auto parseCPERSection(std::span<const std::uint8_t> cperData) -> nlohmann::json
{
    JsonObjectPtr ir(cper_buf_single_section_to_ir(
        reinterpret_cast<const unsigned char*>(cperData.data()),
        cperData.size()));
    return irToJson(ir.get());
}

} // namespace ir

} // namespace libcper
