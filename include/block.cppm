module;

#include <cstdint>
#include <vector>

export module block;
export namespace vaultguard::block {
    struct VaultBlock {
        char header[8] = {'V', 'A', 'U', 'L', 'T', 'G', 'R', 'D'};
        unsigned char prev_hash[32];
        uint32_t key_data_length;
        std::vector<unsigned char> key_data;
        uint64_t next_sector;
        uint32_t checksum;
    };
}
