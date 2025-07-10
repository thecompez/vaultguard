export module utils;

import <cstdint>;
import <vector>;
import <string>;
import <sstream>;
import <iostream>;
import <iomanip>;
import <algorithm>;

export namespace vaultguard::utils {
    const std::string COLOR_CYAN = "\033[1;36m";
    const std::string COLOR_RESET = "\033[0m";

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
        std::stringstream ss;
        ss << prefix << ": ";
        for (size_t i = 0; i < std::min(length, size_t(32)); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        }
        if (length > 32) ss << "...";
        std::println(stderr, "{}Debug: {}{}", COLOR_CYAN, ss.str(), COLOR_RESET);
    }
}