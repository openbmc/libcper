// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#include <fcntl.h>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/vtable.hpp>

#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <limits>
#include <system_error>

struct App
{
    sdbusplus::bus_t bus;
    uint64_t lastIndex;
    std::filesystem::path storageDir;
};

static uint64_t getIndexFromFilesystem(const std::filesystem::path& dir)
{
    uint64_t maxIndex = 0;

    for (const auto& entry : std::filesystem::directory_iterator(dir))
    {
        entry.path();
        if (!entry.is_regular_file())
        {
            continue;
        }

        try
        {
            uint64_t thisIndex = std::stoull(entry.path().stem().string());
            maxIndex = std::max(maxIndex, thisIndex);
        }
        catch (const std::invalid_argument&) // NOLINT(bugprone-empty-catch)
        {
            // not a number
        }
    }
    return maxIndex;
}

static int writeCper(App& app, const std::vector<uint8_t>& sourceBuffer,
                     uint64_t destIndex)
{
    if (sourceBuffer.size() > std::numeric_limits<std::streamsize>::max())
    {
        return EINVAL;
    }

    std::ofstream file(app.storageDir / std::to_string(destIndex),
                       std::ios_base::binary | std::ios_base::trunc |
                           std::ios_base::out);
    if (!file.good())
    {
        return EIO;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    file.write(reinterpret_cast<const char*>(sourceBuffer.data()),
               static_cast<std::streamsize>(sourceBuffer.size()));
    if (!file.good())
    {
        return EIO;
    }

    return 0;
}

static int storeCperHandler(sdbusplus::message::msgp_t msg, void* ctx,
                            sd_bus_error* error)
{
    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    auto cperBytes = message.unpack<std::vector<uint8_t>>();
    ++app.lastIndex;
    auto index = app.lastIndex;
    auto rc = writeCper(app, cperBytes, index);
    if (rc != 0)
    {
        sd_bus_error_set_errno(error, -rc);
        return -rc;
    }
    auto response = message.new_method_return();
    response.append(index);
    response.method_return();
    return 1;
}

static int downloadCperHandler(sdbusplus::message::msgp_t msg, void* ctx,
                               sd_bus_error* error)
{
    auto& app = *static_cast<App*>(ctx);
    sdbusplus::message_t message(msg);
    auto index = message.unpack<uint64_t>();

    auto path = app.storageDir / std::to_string(index);
    auto fd = open(path.c_str(), O_RDONLY, 0);
    if (fd < 0)
    {
        auto rc = errno;
        sd_bus_error_set_errno(error, -rc);
        return -rc;
    }
    auto response = message.new_method_return();
    response.append(static_cast<sdbusplus::message::unix_fd>(fd));
    static_cast<void>(close(fd));
    response.method_return();
    return 1;
}

int main()
{
    const auto* stateDir =
        std::getenv("STATE_DIRECTORY"); // NOLINT(concurrency-mt-unsafe)
    stateDir = stateDir != nullptr ? stateDir : ".";
    auto storageDir = std::filesystem::path(stateDir) / "cpers";
    std::error_code ec;
    std::filesystem::create_directories(storageDir, ec);
    if (ec)
    {
        // NOLINTBEGIN(concurrency-mt-unsafe)
        std::cerr << "cannot create storage directory(" << storageDir
                  << "): " << strerror(ec.value()) << "\n";
        // NOLINTEND(concurrency-mt-unsafe)
        return 1;
    }
    App app{.bus = sdbusplus::bus::new_default(),
            .lastIndex = getIndexFromFilesystem(storageDir),
            .storageDir = std::move(storageDir)};

    std::array<sdbusplus::vtable_t, 4> vtable{
        sdbusplus::vtable::start(),
        sdbusplus::vtable::method("StoreCPER", "ay", "t", storeCperHandler),
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
