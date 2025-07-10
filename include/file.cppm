module;

#include <sodium.h>

export module file;

import <vector>;
import <string>;
import <fstream>;
import <stdexcept>;
import <utility>;

export namespace vaultguard::file {
    void save(const std::string& filename, const std::vector<unsigned char>& salt,
              const std::vector<unsigned char>& encrypted) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing");
        }
        file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        file.close();
    }

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> load(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for reading");
        }

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (size < crypto_pwhash_SALTBYTES) {
            throw std::runtime_error("Invalid file format");
        }

        std::vector<unsigned char> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        file.close();

        std::vector<unsigned char> salt(buffer.begin(), buffer.begin() + crypto_pwhash_SALTBYTES);
        std::vector<unsigned char> encrypted(buffer.begin() + crypto_pwhash_SALTBYTES, buffer.end());
        return {salt, encrypted};
    }
}
