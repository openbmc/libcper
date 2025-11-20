// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include <fcntl.h>
#include <systemd/sd-bus.h>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/vtable.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <new>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

struct App
{
    sdbusplus::bus_t bus;
    uint64_t lastIndex;
    std::filesystem::path storageDir;
};

static uint64_t getIndexFromFilesystem(
    const std::filesystem::directory_iterator& dir)
{
    uint64_t maxIndex = 0;
    uint64_t thisIndex = 0;

    for (const auto& entry : dir)
    {
        if (!entry.is_regular_file())
        {
            continue;
        }
        auto stem = entry.path().stem();
        std::string_view stemView = stem.c_str();
        auto [ptr, ec] =
            std::from_chars(stemView.begin(), stemView.end(), thisIndex);

        if (ec == std::errc() && ptr == stemView.end())
        {
            maxIndex = std::max(maxIndex, thisIndex);
        }
    }
    return maxIndex;
}

static int writeCper(App& app, std::span<uint8_t> sourceBuffer,
                     uint64_t destIndex)
{
    constexpr std::size_t maxCperSize = static_cast<std::size_t>(20 * 1024);
    if (sourceBuffer.size() > maxCperSize)
    {
        return EINVAL;
    }

    std::filesystem::path cperPath;
    try
    {
        cperPath = app.storageDir / std::to_string(destIndex);
    }
    catch (const std::bad_alloc&)
    {
        return ENOMEM;
    }

    std::ofstream file(cperPath, std::ios_base::binary | std::ios_base::trunc |
                                     std::ios_base::out);
    if (!file.good())
    {
        return EIO;
    }

    file.write(std::bit_cast<const char*>(sourceBuffer.data()),
               static_cast<std::streamsize>(sourceBuffer.size()));
    if (!file.good())
    {
        return EIO;
    }

    return 0;
}

static int readCper(App& app, uint64_t sourceIndex,
                    std::vector<uint8_t>& destBuffer)
{
    std::error_code ec;
    std::filesystem::path cperPath;
    try
    {
        cperPath = app.storageDir / std::to_string(sourceIndex);
    }
    catch (const std::bad_alloc&)
    {
        return ENOMEM;
    }

    auto byteCount =
        static_cast<std::size_t>(std::filesystem::file_size(cperPath, ec));
    if (ec)
    {
        return ec.value();
    }

    destBuffer.resize(byteCount);
    std::ifstream file(cperPath, std::ios_base::binary | std::ios_base::in);
    if (!file.good())
    {
        return EIO;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    file.read(std::bit_cast<char*>(destBuffer.data()),
              static_cast<std::streamsize>(destBuffer.size()));
    if (!file.good())
    {
        return EIO;
    }

    return 0;
}

static int storeCperHandler(sdbusplus::message::msgp_t msg, void* ctx,
                            sd_bus_error* error)
{
    if (ctx == nullptr)
    {
        std::abort();
    }

    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    auto cperBytes = message.unpack<std::vector<uint8_t>>();
    ++app.lastIndex;
    auto index = app.lastIndex;
    auto rc = writeCper(app, cperBytes, index);
    if (rc != 0)
    {
        return sd_bus_error_set_errno(error, -rc);
    }
    auto response = message.new_method_return();
    response.append(index);
    response.method_return();
    return 0;
}

static int readCperHandler(sdbusplus::message::msgp_t msg, void* ctx,
                           sd_bus_error* error)
{
    if (ctx == nullptr)
    {
        std::abort();
    }

    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    auto index = message.unpack<uint64_t>();
    std::vector<uint8_t> buffer;
    auto rc = readCper(app, index, buffer);
    if (rc != 0)
    {
        return sd_bus_error_set_errno(error, -rc);
    }
    auto response = message.new_method_return();
    response.append(buffer);
    response.method_return();
    return 0;
}

static int readAllCpersHandler(sdbusplus::message::msgp_t msg, void* ctx,
                               sd_bus_error* error)
{
    if (ctx == nullptr)
    {
        std::abort();
    }

    std::error_code ec;
    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    std::vector<uint8_t> buffer;
    std::map<uint64_t, std::vector<uint8_t>> cpers;
    uint64_t index = 0;

    auto dir = std::filesystem::directory_iterator(app.storageDir, ec);
    if (ec)
    {
        return sd_bus_error_set_errno(error, -ec.value());
    }

    auto response = message.new_method_return();
    for (const auto& entry : dir)
    {
        if (!entry.is_regular_file())
        {
            continue;
        }
        auto stem = entry.path().stem();
        std::string_view stemView = stem.c_str();
        auto [ptr, fromCharsEc] =
            std::from_chars(stemView.begin(), stemView.end(), index);

        if (fromCharsEc == std::errc() && ptr == stemView.end())
        {
            auto rc = readCper(app, index, buffer);
            if (rc != 0)
            {
                return sd_bus_error_set_errno(error, -rc);
            }
            cpers.insert(std::make_pair(index, std::move(buffer)));
        }
    }
    response.append(std::move(cpers));
    response.method_return();
    return 0;
}

static int downloadCperHandler(sdbusplus::message::msgp_t msg, void* ctx,
                               sd_bus_error* error)
{
    if (ctx == nullptr)
    {
        std::abort();
    }

    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    auto index = message.unpack<uint64_t>();

    std::filesystem::path cperPath;
    try
    {
        cperPath = app.storageDir / std::to_string(index);
    }
    catch (const std::bad_alloc&)
    {
        return sd_bus_error_set_errno(error, -ENOMEM);
    }

    auto fd = open(cperPath.c_str(), O_RDONLY, 0);
    if (fd < 0)
    {
        auto rc = errno;
        return sd_bus_error_set_errno(error, -rc);
    }
    auto response = message.new_method_return();
    response.append(static_cast<sdbusplus::message::unix_fd>(fd));
    static_cast<void>(close(fd));
    response.method_return();
    return 0;
}

int main()
{
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    const auto* stateDir = std::getenv("STATE_DIRECTORY");
    stateDir = stateDir != nullptr ? stateDir : ".";
    auto storageDir = std::filesystem::path(stateDir) / "cpers";
    std::error_code ec;
    std::filesystem::create_directories(storageDir, ec);
    if (ec)
    {
        std::cerr << "cannot create storage directory(" << storageDir
                  << "): " << ec.message() << "\n";
        return 1;
    }

    std::filesystem::directory_iterator dir(storageDir, ec);
    if (ec)
    {
        std::cerr << "cannot read storage directory(" << storageDir
                  << "): " << ec.message() << "\n";
        return 1;
    }

    App app{.bus = sdbusplus::bus::new_default(),
            .lastIndex = getIndexFromFilesystem(dir),
            .storageDir = std::move(storageDir)};

    std::array<sdbusplus::vtable_t, 6> vtable{
        sdbusplus::vtable::start(),
        sdbusplus::vtable::method("StoreCPER", "ay", "t", storeCperHandler),
        sdbusplus::vtable::method("ReadCPER", "t", "ay", readCperHandler),
        sdbusplus::vtable::method("ReadAllCPERs", "", "a{tay}",
                                  readAllCpersHandler),
        sdbusplus::vtable::method("DownloadCPER", "t", "h",
                                  downloadCperHandler),
        sdbusplus::vtable::end(),
    };

    sdbusplus::server::interface_t iface(
        app.bus, "/xyz/openbmc_project/CPERRepository1",
        "xyz.openbmc_project.CPERRepository1", vtable.data(), &app);
    sdbusplus::server::manager_t objectManager(
        app.bus, "/xyz/openbmc_project/CPERRepository1");

    try
    {
        app.bus.request_name("xyz.openbmc_project.CPERRepository1");
        app.bus.process_loop();
    }
    catch (const sdbusplus::exception_t& e)
    {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
