module;

#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>
#include <string_view>
#include <format>

export module utils;

export namespace vaultguard::utils {
    const std::string COLOR_CYAN = "\033[1;36m";
    const std::string COLOR_RESET = "\033[0m";

    bool is_debug_enabled() {
        static const bool enabled = [] {
            const char* env_value = std::getenv("VAULTGUARD_DEBUG");
            return env_value != nullptr && std::string_view(env_value) == "1";
        }();
        return enabled;
    }

    uint32_t crc32(const unsigned char* data, size_t length) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < length; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }

    void debug_buffer(const std::string& prefix, const unsigned char* buffer, size_t length) {
        if (!is_debug_enabled()) {
            return;
        }
        std::stringstream ss;
        ss << prefix << ": ";
        for (size_t i = 0; i < std::min(length, size_t(32)); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        }
        if (length > 32) ss << "...";
        std::cerr << std::format("{}Debug: {}{}", COLOR_CYAN, ss.str(), COLOR_RESET) << '\n';
    }
}
