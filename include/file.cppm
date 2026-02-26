module;

#include <sodium.h>

export module file;

import <vector>;
import <string>;
import <fstream>;
import <stdexcept>;
import <utility>;
import <array>;
import <filesystem>;
import <system_error>;
import <cstdint>;
import <cstring>;
import <cstddef>;

export namespace vaultguard::file {
    constexpr std::array<unsigned char, 8> FILE_MAGIC = {'V', 'G', 'F', 'I', 'L', 'E', '0', '1'};

    void save(const std::string& filename, const std::vector<unsigned char>& salt,
              const std::vector<unsigned char>& encrypted) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing");
        }

        file.write(reinterpret_cast<const char*>(FILE_MAGIC.data()), static_cast<std::streamsize>(FILE_MAGIC.size()));
        file.write(reinterpret_cast<const char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
        file.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
        file.flush();
        if (!file) {
            file.close();
            throw std::runtime_error("Failed while writing encrypted file contents");
        }
        file.close();

        std::error_code permissions_error;
        std::filesystem::permissions(
            filename,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            permissions_error);
        (void)permissions_error;
    }

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> load(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for reading");
        }

        file.seekg(0, std::ios::end);
        const std::streamoff end_pos = file.tellg();
        if (end_pos < 0) {
            throw std::runtime_error("Failed to determine file size");
        }
        const size_t size = static_cast<size_t>(end_pos);
        file.seekg(0, std::ios::beg);

        if (size < crypto_pwhash_SALTBYTES) {
            throw std::runtime_error("Invalid file format");
        }

        std::vector<unsigned char> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
        if (!file) {
            file.close();
            throw std::runtime_error("Failed to read encrypted file contents");
        }
        file.close();

        size_t offset = 0;
        if (size >= FILE_MAGIC.size() + crypto_pwhash_SALTBYTES &&
            std::memcmp(buffer.data(), FILE_MAGIC.data(), FILE_MAGIC.size()) == 0) {
            offset = FILE_MAGIC.size();
        }

        if (size < offset + crypto_pwhash_SALTBYTES) {
            throw std::runtime_error("Invalid file format");
        }

        std::vector<unsigned char> salt(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
                                        buffer.begin() + static_cast<std::ptrdiff_t>(offset + crypto_pwhash_SALTBYTES));
        std::vector<unsigned char> encrypted(buffer.begin() + static_cast<std::ptrdiff_t>(offset + crypto_pwhash_SALTBYTES),
                                             buffer.end());
        if (encrypted.empty()) {
            throw std::runtime_error("Invalid file format");
        }
        return {salt, encrypted};
    }
}
