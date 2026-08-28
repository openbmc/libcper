#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <span>

/**
 * @file libcper.hpp
 * @brief C++ bindings for libcper
 *
 * These bindings produce nlohmann::json representations of CPER data instead
 * of the json-c format used in the C-bindings.
 *
 * An unparseable or invalid record is represented as a null nlohmann::json
 * value, mirroring the existing C API which returns NULL.
 */

namespace libcper
{

/** Functions that generate libcper Intermediate Representation */
namespace ir
{
/**
 * @brief Parses a full CPER record into its libcper IR representation.
 *
 * @param[in] cperData The CPER record data.
 *
 * @return The IR representation as nlohmann::json, or a null json value if
 *         the input is not a valid CPER record.
 */
auto parseCPER(std::span<const std::uint8_t> cperData) -> nlohmann::json;

/**
 * @brief Parses a single CPER section into its libcper IR representation.
 *
 * @param[in] cperData The CPER section data, including its section
 *                     descriptor.
 *
 * @return The IR representation as nlohmann::json, or a null json value on
 *         failure.
 */
auto parseCPERSection(std::span<const std::uint8_t> cperData) -> nlohmann::json;
} // namespace ir

} // namespace libcper
