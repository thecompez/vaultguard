import crypto;
import block;
import utils;

using namespace vaultguard::block;

#include <sodium.h>
#include <string>
#include <vector>
#include <print>
#include <format>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <filesystem>

namespace vaultguard::wallet {
const std::string COLOR_RED = "\033[1;31m";
const std::string COLOR_GREEN = "\033[1;32m";
const std::string COLOR_CYAN = "\033[1;36m";
const std::string COLOR_RESET = "\033[0m";
    

bool read_block_from_sector(const std::string& file_path, uint64_t sector, VaultBlock& block) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) {
        std::println(stderr, "{}Error: Cannot open file {} for reading (errno: {}).{}", COLOR_RED, file_path, errno, COLOR_RESET);
        return false;
    }
    in.seekg(sector * 512);
    if (!in) {
        std::println(stderr, "{}Error: Cannot seek to sector {} in file {} (errno: {}).{}", COLOR_RED, sector, file_path, errno, COLOR_RESET);
        in.close();
        return false;
    }
    std::vector<unsigned char> buffer(512);
    in.read(reinterpret_cast<char*>(buffer.data()), 512);
    if (in.gcount() != 512) {
        std::println(stderr, "{}Error: Failed to read 512 bytes from sector {} in file {} (read {} bytes, errno: {}).{}", COLOR_RED, sector, file_path, in.gcount(), errno, COLOR_RESET);
        in.close();
        return false;
    }
    in.close();
    utils::debug_buffer("Read buffer from sector " + std::to_string(sector), buffer.data(), 512);
    if (std::strncmp(reinterpret_cast<char*>(buffer.data()), "VAULTGRD", 8) != 0) {
        std::println(stderr, "{}Error: Invalid header in sector {} of file {}. Expected 'VAULTGRD'.{}", COLOR_RED, sector, file_path, COLOR_RESET);
        return false;
    }
    uint32_t checksum;
    std::memcpy(&checksum, buffer.data() + 508, 4);
    if (checksum != utils::crc32(buffer.data(), 512 - 4)) {
        std::println(stderr, "{}Error: Checksum mismatch for sector {} in file {}.{}", COLOR_RED, sector, file_path, COLOR_RESET);
        return false;
    }
    std::memcpy(block.header, buffer.data(), 8);
    std::memcpy(block.prev_hash, buffer.data() + 8, 32);
    std::memcpy(&block.key_data_length, buffer.data() + 40, 4);
    if (block.key_data_length > 456) {
        std::println(stderr, "{}Error: Invalid key_data_length {} in sector {} (max allowed 456).{}", COLOR_RED, block.key_data_length, sector, COLOR_RESET);
        return false;
    }
    block.key_data.resize(block.key_data_length);
    std::memcpy(block.key_data.data(), buffer.data() + 44, block.key_data_length);
    std::memcpy(&block.next_sector, buffer.data() + 44 + block.key_data_length, 8);
    block.checksum = checksum;
    return true;
}

std::string recover_key_from_blockchain(const std::string& device_path, const std::string& password) {
    std::println(stderr, "{}Debug: Attempting to recover key with password (length: {}, content: {}).{}", COLOR_CYAN, password.length(), password, COLOR_RESET);
    const int NUM_COPIES = 3;
    const uint64_t START_SECTOR = 1000;
    std::vector<uint64_t> sectors = {START_SECTOR, START_SECTOR + 100, START_SECTOR + 200};
    std::string sector_file = device_path + "/vault_sectors.dat";

    if (!std::filesystem::exists(sector_file)) {
        std::println(stderr, "{}Error: Sector file {} does not exist.{}", COLOR_RED, sector_file, COLOR_RESET);
        return "";
    }

    for (uint64_t sector : sectors) {
        VaultBlock block;
        if (read_block_from_sector(sector_file, sector, block)) {
            // تغییر: حالا از block.key_data_length استفاده می‌کنی، پس چک رو بر اساس length واقعی انجام بده
            if (block.key_data_length < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
                std::println(stderr, "{}Error: Insufficient key data size in sector {} of file {}. Expected at least {} bytes, got {}.{}",
                             COLOR_RED, sector, sector_file, crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES, block.key_data_length, COLOR_RESET);
                continue;
            }
            unsigned char nonce[crypto_secretbox_NONCEBYTES];
            std::memcpy(nonce, block.key_data.data(), crypto_secretbox_NONCEBYTES);
            utils::debug_buffer("Recovered nonce from sector " + std::to_string(sector), nonce, crypto_secretbox_NONCEBYTES);
            std::vector<unsigned char> ciphertext(block.key_data_length - crypto_secretbox_NONCEBYTES);
            std::memcpy(ciphertext.data(), block.key_data.data() + crypto_secretbox_NONCEBYTES, ciphertext.size());
            utils::debug_buffer("Recovered ciphertext from sector " + std::to_string(sector), ciphertext.data(), ciphertext.size());
            unsigned char derived_key[crypto_secretbox_KEYBYTES];
            crypto_kdf_derive_from_key(derived_key, crypto_secretbox_KEYBYTES, 1, "vaultguard", reinterpret_cast<const unsigned char*>(password.data()));
            utils::debug_buffer("Derived key for decryption", derived_key, crypto_secretbox_KEYBYTES);
            std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
            if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce, derived_key) == 0) {
                std::string key(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
                crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
                std::println("{}", COLOR_GREEN);
                std::println("Key recovered from sector {} of {}. Your digital vault is unlocked! 🔓", sector, sector_file);
                std::println("Recovered key: {}", key);
                std::println("{}", COLOR_RESET);
                return key;
            } else {
                std::println(stderr, "{}Error: Failed to decrypt key from sector {} in {}. Incorrect password or corrupted data.{}", COLOR_RED, sector, sector_file, COLOR_RESET);
            }
            crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
        }
    }
    std::println(stderr, "{}Error: Failed to recover key from blockchain in {}. Check if the file exists and is accessible.{}", COLOR_RED, sector_file, COLOR_RESET);
    return "";
}
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::println(stderr, "{}Usage: {} <mount_path> <password>{}", vaultguard::wallet::COLOR_RED, argv[0], vaultguard::wallet::COLOR_RESET);
        return 1;
    }
    if (sodium_init() == -1) {
        std::println(stderr, "{}Error: Failed to initialize libsodium.{}", vaultguard::wallet::COLOR_RED, vaultguard::wallet::COLOR_RESET);
        return 1;
    }
    std::string device_path = argv[1];
    std::string password = argv[2];
    std::string recovered_key = vaultguard::wallet::recover_key_from_blockchain(device_path, password);
    if (!recovered_key.empty()) {
        std::println("{}", vaultguard::wallet::COLOR_GREEN);
        std::println("Recovered key: {}", recovered_key);
        std::println("{}", vaultguard::wallet::COLOR_RESET);
    }
    return 0;
}