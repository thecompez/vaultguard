module;

#include <print>
#include <format>
#include <string>
#include <vector>
#include <utility>
#include <cctype>
#include <ctime>
#include <array>
#include <span>
#include <fstream>
#include <sstream>
#include <sodium.h>
#include <regex>
#include <filesystem>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <system_error>

#ifdef __unix__
#include <termios.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

export module wallet;

import crypto;
import block;
import file;
import utils;

using namespace vaultguard::block;

export namespace vaultguard::wallet {
// ANSI color codes for console output
const std::string COLOR_RED = "\033[1;31m";
const std::string COLOR_YELLOW = "\033[1;33m";
const std::string COLOR_GREEN = "\033[1;32m";
const std::string COLOR_CYAN = "\033[1;36m";
const std::string COLOR_RESET = "\033[0m";

// Software metadata
const std::string VERSION = "1.1.0";
const std::string AUTHOR = "Genyleap";
constexpr size_t SECTOR_SIZE = 512;
constexpr size_t HEADER_SIZE = 8;
constexpr size_t PREV_HASH_SIZE = 32;
constexpr size_t KEY_LENGTH_OFFSET = HEADER_SIZE + PREV_HASH_SIZE; // 40
constexpr size_t KEY_DATA_OFFSET = KEY_LENGTH_OFFSET + sizeof(uint32_t); // 44
constexpr size_t NEXT_SECTOR_SIZE = sizeof(uint64_t); // 8
constexpr size_t CHECKSUM_SIZE = sizeof(uint32_t); // 4
constexpr size_t CHECKSUM_OFFSET = SECTOR_SIZE - CHECKSUM_SIZE; // 508
constexpr size_t MAX_KEY_DATA_LENGTH = CHECKSUM_OFFSET - KEY_DATA_OFFSET - NEXT_SECTOR_SIZE; // 456

void secure_zero_string(std::string& value) {
    if (!value.empty()) {
        crypto::secure_zero(value.data(), value.size());
        value.clear();
    }
}

void trim_trailing_newlines(std::string& value) {
    const size_t pos = value.find_last_not_of("\n\r");
    if (pos == std::string::npos) {
        value.clear();
        return;
    }
    value.erase(pos + 1);
}

bool is_valid_drive_name(const std::string& drive_name) {
    static const std::regex allowed_pattern(R"(^[A-Za-z0-9._-]{1,32}$)");
    return std::regex_match(drive_name, allowed_pattern);
}

bool is_valid_wallet_id(const std::string& wallet_id) {
    static const std::regex allowed_pattern(R"(^[A-Za-z0-9_-]{1,64}$)");
    return std::regex_match(wallet_id, allowed_pattern);
}

bool is_safe_wallet_data_file(const std::string& file_name) {
    static const std::regex allowed_pattern(R"(^wallet_[A-Za-z0-9_-]{1,64}\.dat$)");
    return std::regex_match(file_name, allowed_pattern);
}

bool constant_time_equal(const std::string& left, const std::string& right) {
    if (left.size() != right.size()) {
        return false;
    }
    if (left.empty()) {
        return true;
    }
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool is_valid_device_path(const std::string& device_path) {
#ifdef __APPLE__
    static const std::regex allowed_pattern(R"(^/dev/disk[0-9]+$)");
    return std::regex_match(device_path, allowed_pattern);
#elif defined(__linux__)
    static const std::regex allowed_pattern(R"(^/dev/(sd[a-z]|nvme[0-9]+n[0-9]+)$)");
    return std::regex_match(device_path, allowed_pattern);
#elif defined(_WIN32)
    static const std::regex allowed_pattern(R"(^\\\\\.\\PhysicalDrive[0-9]+$)");
    return std::regex_match(device_path, allowed_pattern);
#else
    return false;
#endif
}

std::string shell_quote(const std::string& input) {
    std::string quoted;
    quoted.reserve(input.size() + 2);
    quoted.push_back('\'');
    for (char c : input) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

// Write block to file-based "sector"
bool write_block_to_sector(const std::string& file_path, uint64_t sector, const VaultBlock& block) {
    if (block.key_data.size() > MAX_KEY_DATA_LENGTH) {
        std::println(stderr, "{}Error: key_data is too large for sector layout ({} > {}).{}",
                     COLOR_RED, block.key_data.size(), MAX_KEY_DATA_LENGTH, COLOR_RESET);
        return false;
    }

    std::ofstream out(file_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!out) {
        // Create file if it doesn't exist
        out.open(file_path, std::ios::binary | std::ios::out);
        if (!out) {
            std::println(stderr, "{}Error: Cannot open file {} for writing (errno: {}).{}", COLOR_RED, file_path, errno, COLOR_RESET);
            return false;
        }
        // Initialize file with enough space for sectors
        out.seekp(512 * 1200 - 1);
        out.write("", 1);
        out.close();
        out.open(file_path, std::ios::binary | std::ios::in | std::ios::out);
    }
    if (!out) {
        std::println(stderr, "{}Error: Cannot open file {} for writing (errno: {}).{}", COLOR_RED, file_path, errno, COLOR_RESET);
        return false;
    }
    out.seekp(static_cast<std::streamoff>(sector * SECTOR_SIZE));
    if (!out) {
        std::println(stderr, "{}Error: Cannot seek to sector {} in file {} (errno: {}).{}", COLOR_RED, sector, file_path, errno, COLOR_RESET);
        out.close();
        return false;
    }

    const uint32_t key_data_length = static_cast<uint32_t>(block.key_data.size());
    const size_t next_sector_offset = KEY_DATA_OFFSET + key_data_length;
    if (next_sector_offset + NEXT_SECTOR_SIZE > CHECKSUM_OFFSET) {
        std::println(stderr, "{}Error: Invalid block layout for sector {} (payload overrun).{}", COLOR_RED, sector, COLOR_RESET);
        out.close();
        return false;
    }

    std::array<unsigned char, SECTOR_SIZE> buffer {};
    std::memcpy(buffer.data(), block.header, 8);
    std::memcpy(buffer.data() + 8, block.prev_hash, 32);
    std::memcpy(buffer.data() + KEY_LENGTH_OFFSET, &key_data_length, sizeof(key_data_length));
    if (key_data_length > 0) {
        std::memcpy(buffer.data() + KEY_DATA_OFFSET, block.key_data.data(), key_data_length);
    }
    std::memcpy(buffer.data() + next_sector_offset, &block.next_sector, NEXT_SECTOR_SIZE);

    uint32_t checksum = utils::crc32(buffer.data(), CHECKSUM_OFFSET);
    std::memcpy(buffer.data() + CHECKSUM_OFFSET, &checksum, CHECKSUM_SIZE);

    out.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(SECTOR_SIZE));
    if (!out) {
        std::println(stderr, "{}Error: Failed to write block to sector {} in file {} (errno: {}).{}", COLOR_RED, sector, file_path, errno, COLOR_RESET);
        out.close();
        return false;
    }
    out.close();
    if (utils::is_debug_enabled()) {
        std::println(stderr, "{}Debug: Successfully wrote block to sector {} in file {}.{}", COLOR_CYAN, sector, file_path, COLOR_RESET);
    }
    return true;
}


// Read block from file-based "sector"
bool read_block_from_sector(const std::string& file_path, uint64_t sector, VaultBlock& block) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) {
        std::println(stderr, "{}Error: Cannot open file {} for reading (errno: {}).{}", COLOR_RED, file_path, errno, COLOR_RESET);
        return false;
    }
    in.seekg(static_cast<std::streamoff>(sector * SECTOR_SIZE));
    if (!in) {
        std::println(stderr, "{}Error: Cannot seek to sector {} in file {} (errno: {}).{}", COLOR_RED, sector, file_path, errno, COLOR_RESET);
        in.close();
        return false;
    }
    std::array<unsigned char, SECTOR_SIZE> buffer {};
    in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(SECTOR_SIZE));
    if (in.gcount() != static_cast<std::streamsize>(SECTOR_SIZE)) {
        std::println(stderr, "{}Error: Failed to read {} bytes from sector {} in file {} (read {} bytes, errno: {}).{}",
                     COLOR_RED, SECTOR_SIZE, sector, file_path, in.gcount(), errno, COLOR_RESET);
        in.close();
        return false;
    }
    in.close();

    if (std::strncmp(reinterpret_cast<char*>(buffer.data()), "VAULTGRD", 8) != 0) {
        std::println(stderr, "{}Error: Invalid header in sector {} of file {}. Expected 'VAULTGRD'.{}", COLOR_RED, sector, file_path, COLOR_RESET);
        return false;
    }

    uint32_t checksum;
    std::memcpy(&checksum, buffer.data() + CHECKSUM_OFFSET, CHECKSUM_SIZE);
    if (checksum != utils::crc32(buffer.data(), CHECKSUM_OFFSET)) {
        std::println(stderr, "{}Error: Checksum mismatch for sector {} in file {}.{}", COLOR_RED, sector, file_path, COLOR_RESET);
        return false;
    }

    std::memcpy(block.header, buffer.data(), 8);
    std::memcpy(block.prev_hash, buffer.data() + 8, 32);

    uint32_t key_data_length = 0;
    std::memcpy(&key_data_length, buffer.data() + KEY_LENGTH_OFFSET, sizeof(key_data_length));
    if (key_data_length > MAX_KEY_DATA_LENGTH) {
        std::println(stderr, "{}Error: Invalid key_data_length {} in sector {} (max allowed {}).{}",
                     COLOR_RED, key_data_length, sector, MAX_KEY_DATA_LENGTH, COLOR_RESET);
        return false;
    }

    const size_t next_sector_offset = KEY_DATA_OFFSET + key_data_length;
    if (next_sector_offset + NEXT_SECTOR_SIZE > CHECKSUM_OFFSET) {
        std::println(stderr, "{}Error: Corrupted block layout in sector {}.{}", COLOR_RED, sector, COLOR_RESET);
        return false;
    }

    block.key_data_length = key_data_length;
    block.key_data.resize(key_data_length);
    if (key_data_length > 0) {
        std::memcpy(block.key_data.data(), buffer.data() + KEY_DATA_OFFSET, key_data_length);
    }
    std::memcpy(&block.next_sector, buffer.data() + next_sector_offset, NEXT_SECTOR_SIZE);
    block.checksum = checksum;
    return true;
}



// Store key in blockchain
bool store_key_in_blockchain(const std::string& device_path, const std::string& key, const std::string& password, const std::string& output_path) {
    (void)device_path;
    const int NUM_COPIES = 3;
    const uint64_t START_SECTOR = 1000;
    std::vector<uint64_t> sectors = {START_SECTOR, START_SECTOR + 100, START_SECTOR + 200};
    std::string sector_file = output_path + "/vault_sectors.dat";
    unsigned char prev_hash[32] = {0};

    // Generate salt for key derivation with Argon2.
    auto salt = crypto::generate_salt();
    auto key_vec = crypto::derive_key(password, salt);
    unsigned char derived_key[crypto_secretbox_KEYBYTES];
    std::copy(key_vec.begin(), key_vec.end(), derived_key);
    crypto::secure_zero(key_vec.data(), key_vec.size());
    bool success = false;

    for (int i = 0; i < NUM_COPIES; ++i) {
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

        std::vector<unsigned char> ciphertext(key.size() + crypto_secretbox_MACBYTES);
        int ret = crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(key.data()), key.size(), nonce, derived_key);
        if (ret != 0) {
            std::println(stderr, "{}Error: Failed to encrypt key for sector {} (crypto_secretbox_easy returned {}).{}", COLOR_RED, sectors[i], ret, COLOR_RESET);
            continue;
        }

        std::vector<unsigned char> key_data(salt.size() + crypto_secretbox_NONCEBYTES + ciphertext.size());
        std::memcpy(key_data.data(), salt.data(), salt.size());
        std::memcpy(key_data.data() + salt.size(), nonce, crypto_secretbox_NONCEBYTES);
        std::memcpy(key_data.data() + salt.size() + crypto_secretbox_NONCEBYTES, ciphertext.data(), ciphertext.size());
        if (key_data.size() > MAX_KEY_DATA_LENGTH) {
            std::println(stderr, "{}Error: Encrypted key payload is too large for a sector ({} > {}).{}",
                         COLOR_RED, key_data.size(), MAX_KEY_DATA_LENGTH, COLOR_RESET);
            continue;
        }

        VaultBlock block;
        std::memcpy(block.prev_hash, prev_hash, 32);
        block.key_data = key_data;
        block.key_data_length = static_cast<uint32_t>(key_data.size());
        block.next_sector = (i < NUM_COPIES - 1) ? sectors[i + 1] : 0;
        if (write_block_to_sector(sector_file, sectors[i], block)) {
            std::array<unsigned char, SECTOR_SIZE> serialized_block {};
            std::memcpy(serialized_block.data(), block.header, HEADER_SIZE);
            std::memcpy(serialized_block.data() + HEADER_SIZE, block.prev_hash, PREV_HASH_SIZE);
            std::memcpy(serialized_block.data() + KEY_LENGTH_OFFSET, &block.key_data_length, sizeof(block.key_data_length));
            std::memcpy(serialized_block.data() + KEY_DATA_OFFSET, block.key_data.data(), block.key_data_length);
            const size_t next_sector_offset = KEY_DATA_OFFSET + block.key_data_length;
            std::memcpy(serialized_block.data() + next_sector_offset, &block.next_sector, NEXT_SECTOR_SIZE);
            block.checksum = utils::crc32(serialized_block.data(), CHECKSUM_OFFSET);
            std::memcpy(serialized_block.data() + CHECKSUM_OFFSET, &block.checksum, CHECKSUM_SIZE);
            crypto_hash_sha256(prev_hash, serialized_block.data(), SECTOR_SIZE);
            std::println("{}", COLOR_GREEN);
            std::println("Key stored in sector {} of {}. Your keys are locked in an unbreakable digital vault! 🔒", sectors[i], sector_file);
            std::println("{}", COLOR_RESET);
            success = true;
        } else {
            std::println(stderr, "{}Error: Failed to write block to sector {}.{}", COLOR_RED, sectors[i], COLOR_RESET);
        }
    }

    // Fallback to filesystem if sector storage fails
    if (!success) {
        std::println("{}", COLOR_YELLOW);
        std::println("Warning: Failed to store key in sectors. Saving to filesystem as fallback.");
        std::println("{}", COLOR_RESET);
        std::string key_file = output_path + "/vault_key.dat";
        std::ofstream out(key_file, std::ios::binary);
        if (!out) {
            std::println(stderr, "{}Error: Failed to save key to {} (errno: {}).{}", COLOR_RED, key_file, errno, COLOR_RESET);
            crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
            return false;
        }

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
        std::vector<unsigned char> ciphertext(key.size() + crypto_secretbox_MACBYTES);
        if (crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(key.data()), key.size(), nonce, derived_key) == 0) {
            std::vector<unsigned char> key_data(salt.size() + crypto_secretbox_NONCEBYTES + ciphertext.size());
            std::memcpy(key_data.data(), salt.data(), salt.size());
            std::memcpy(key_data.data() + salt.size(), nonce, crypto_secretbox_NONCEBYTES);
            std::memcpy(key_data.data() + salt.size() + crypto_secretbox_NONCEBYTES, ciphertext.data(), ciphertext.size());
            out.write(reinterpret_cast<const char*>(key_data.data()), static_cast<std::streamsize>(key_data.size()));
            out.close();

            std::error_code permissions_error;
            std::filesystem::permissions(
                key_file,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                permissions_error);
            if (permissions_error) {
                std::println(stderr, "{}Warning: Failed to enforce strict permissions on {}: {}.{}",
                             COLOR_YELLOW, key_file, permissions_error.message(), COLOR_RESET);
            }

            std::println("{}", COLOR_GREEN);
            std::println("Key saved to {} as fallback.{}", key_file, COLOR_RESET);
            success = true;
        } else {
            std::println(stderr, "{}Error: Failed to encrypt key for fallback file {}.{}", COLOR_RED, key_file, COLOR_RESET);
        }
    }

    crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
    return success;
}

// Recover key from blockchain
std::string recover_key_from_blockchain(const std::string& device_path, const std::string& password) {
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
            if (block.key_data_length < crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
                std::println(stderr, "{}Error: Insufficient key data size in sector {} of file {}. Expected at least {} bytes, got {}.{}",
                             COLOR_RED, sector, sector_file, crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES, block.key_data_length, COLOR_RESET);
                continue;
            }
            std::vector<unsigned char> recovered_salt(block.key_data.begin(), block.key_data.begin() + crypto_pwhash_SALTBYTES);
            auto key_vec = crypto::derive_key(password, recovered_salt);
            unsigned char derived_key[crypto_secretbox_KEYBYTES];
            std::copy(key_vec.begin(), key_vec.end(), derived_key);
            crypto::secure_zero(key_vec.data(), key_vec.size());
            unsigned char nonce[crypto_secretbox_NONCEBYTES];
            std::memcpy(nonce, block.key_data.data() + crypto_pwhash_SALTBYTES, crypto_secretbox_NONCEBYTES);
            std::vector<unsigned char> ciphertext(block.key_data_length - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES);
            std::memcpy(ciphertext.data(), block.key_data.data() + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES, ciphertext.size());
            std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
            if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce, derived_key) == 0) {
                std::string key(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
                crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
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

// Fallback: Recover key from filesystem
std::string recover_key_from_filesystem(const std::string& output_path, const std::string& password) {
    std::string key_file = output_path + "/vault_key.dat";
    std::ifstream in(key_file, std::ios::binary);
    if (!in) {
        std::println(stderr, "{}Warning: Cannot open {} for reading (errno: {}). Fallback file not found, which is expected if blockchain storage succeeded.{}", COLOR_YELLOW, key_file, errno, COLOR_RESET);
        return "";
    }
    std::vector<unsigned char> key_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    if (key_data.size() < crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        std::println(stderr, "{}Error: Invalid key data in {}. File is too small or corrupted.{}", COLOR_RED, key_file, COLOR_RESET);
        return "";
    }
    std::vector<unsigned char> recovered_salt(key_data.begin(), key_data.begin() + crypto_pwhash_SALTBYTES);
    auto key_vec = crypto::derive_key(password, recovered_salt);
    unsigned char derived_key[crypto_secretbox_KEYBYTES];
    std::copy(key_vec.begin(), key_vec.end(), derived_key);
    crypto::secure_zero(key_vec.data(), key_vec.size());
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    std::memcpy(nonce, key_data.data() + crypto_pwhash_SALTBYTES, crypto_secretbox_NONCEBYTES);
    std::vector<unsigned char> ciphertext(key_data.size() - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES);
    std::memcpy(ciphertext.data(), key_data.data() + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES, ciphertext.size());
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(), nonce, derived_key) == 0) {
        std::string key(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
        crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
        return key;
    }
    crypto::secure_zero(derived_key, crypto_secretbox_KEYBYTES);
    std::println(stderr, "{}Error: Failed to decrypt key from {}. Incorrect password or corrupted file.{}", COLOR_RED, key_file, COLOR_RESET);
    return "";
}

// Display startup banner
void display_banner() {
    std::println("{}", COLOR_CYAN);
    std::println("----------------------------------------");
    std::println("VaultGuard v{}", VERSION);
    std::println("Secure Wallet Storage and Recovery");
    std::println("Author: {}", AUTHOR);
    std::println("Description: Securely store and recover cryptocurrency wallets (private keys and seed phrases) on an encrypted USB drive.");
    std::println("----------------------------------------{}", COLOR_RESET);
    std::println("{}", COLOR_YELLOW);
    std::println("WARNING: Run this program OFFLINE on a trusted system or live USB (e.g., Tails) for maximum security.");
    std::println("Do NOT run on a system with potential malware or keyloggers.");
    std::println("Ensure a USB drive is connected before proceeding.{}", COLOR_RESET);
}

// Check if a directory is writable
bool is_writable(const std::filesystem::path& dir) {
    const std::string nonce = std::format("{}_{}", std::time(nullptr), static_cast<long long>(::getpid()));
    std::filesystem::path test_file = dir / (".vaultguard_write_test_" + nonce);
    std::ofstream test(test_file);
    if (!test) {
        return false;
    }
    test.close();
    std::error_code remove_error;
    std::filesystem::remove(test_file, remove_error);
    return true;
}

// Get secure input with hidden characters
std::string get_secure_input(const std::string& prompt) {
    if (!prompt.empty()) {
        std::print("{}{}: {}", COLOR_CYAN, prompt, COLOR_RESET);
        std::fflush(stdout);
    }

#ifdef __unix__
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#elif defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
#endif

    std::string input;
    std::getline(std::cin, input);
    trim_trailing_newlines(input);

#ifdef __unix__
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#elif defined(_WIN32)
    SetConsoleMode(hStdin, mode);
#endif
    std::println("");  // Newline after input
    return input;
}

// Read data from a file
std::string read_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error(std::format("Failed to open file: {}. Ensure the file exists and is accessible (e.g., contains private key and seed phrase, one per line).", filename));
    }
    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return data;
}

// List USB drives
struct UsbDevice {
    std::string path;
    std::string name;
    std::string size;
};

std::vector<UsbDevice> list_usb_drives() {
    std::vector<UsbDevice> devices;
#ifdef __APPLE__
    FILE* pipe = popen("diskutil list external | awk 'BEGIN { disk = \"\" } /^ *\\/dev\\/disk[0-9]+ \\(external, physical\\)/ { disk = $1; next } /^[[:space:]]+[0-9]+:/ { if ($2 ~ /Apple_APFS|Apple_HFS|Windows_NTFS|DOS_FAT_32/) { size = $(NF-2) \" \" $(NF-1); gsub(/\\+/, \"\", size); vol = \"\"; for (i=3; i<=NF-3; ++i) vol = vol \" \" $i; gsub(/^ +| +$/, \"\", vol); if (vol != \"\" && vol != \"EFI\" && size !~ /MB/) { printf \"%s \\\"%s\\\" %s\\n\", disk, vol, size } } }'", "r");
#elif defined(__linux__)
    FILE* pipe = popen("lsblk -d -o NAME,SIZE,LABEL | grep -v 'loop\\|sda\\|nvme'", "r");
#elif defined(_WIN32)
    FILE* pipe = popen("powershell -Command \"Get-Disk | Where-Object {$_.BusType -eq 'USB'} | Select-Object Number,@{Name='Size';Expression={[math]::Round($_.Size/1GB,2) + ' GB'}},FriendlyName | Format-Table -AutoSize | Out-String\"", "r");
#else
    throw std::runtime_error("Unsupported platform for listing USB drives");
#endif
    if (!pipe) throw std::runtime_error("Failed to list USB drives");

    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        std::istringstream line_stream(line);
        std::string path, name, size;
        line_stream >> path;
        std::getline(line_stream >> std::ws, name, '"');
        std::getline(line_stream >> std::ws, name, '"');
        std::getline(line_stream >> std::ws, size);
        size = std::regex_replace(size, std::regex("\\s*disk[0-9]+\\s*"), "");
        while (!name.empty() && (name[0] == ' ' || name[0] == '\t' || name[0] == '(')) name.erase(0, 1);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\n' || name.back() == '\r' || name.back() == ')')) name.pop_back();
        while (!size.empty() && (size[0] == ' ' || size[0] == '\t' || size[0] == '*')) size.erase(0, 1);
        while (!size.empty() && (size.back() == ' ' || size.back() == '\n' || size.back() == '\r')) size.pop_back();
        if (!path.empty() && !name.empty() && !size.empty()) {
            devices.push_back({path, name, size});
        }
    }

    if (devices.empty()) {
        if (utils::is_debug_enabled()) {
            std::println(stderr, "{}Debug: Raw output from diskutil list external:\n{}", COLOR_RED, output);
            std::println(stderr, "{}", COLOR_RESET);
        }
    }

    return devices;
}

// Check if a device is a system disk
bool is_system_disk(const std::string& device_path) {
#ifdef __APPLE__
    return device_path == "/dev/disk0" || device_path == "/dev/disk1";
#elif defined(__linux__)
    return device_path == "/dev/sda" || device_path == "/dev/nvme0n1";
#elif defined(_WIN32)
    return device_path == "C:" || device_path == "C";
#else
    return false;
#endif
}

// Get APFS volume path
std::string get_apfs_volume_path(const std::string& device_path) {
    return device_path; // Not needed with file-based sectors
}

// Format USB drive to APFS (non-encrypted)
bool format_usb_drive(const std::string& device_path, const std::string& drive_name, const std::string& disk_name, const std::string& password, std::string& output_path) {
    if (!is_valid_device_path(device_path)) {
        std::println(stderr, "{}ERROR: Invalid device path format: {}.{}", COLOR_RED, device_path, COLOR_RESET);
        return false;
    }
    if (!is_valid_drive_name(drive_name)) {
        std::println(stderr, "{}ERROR: Invalid drive name '{}'. Use only letters, digits, dot, dash, underscore (max 32).{}",
                     COLOR_RED, drive_name, COLOR_RESET);
        return false;
    }

    if (is_system_disk(device_path)) {
        std::println(stderr, "{}ERROR: Cannot format system disk: {}", COLOR_RED, device_path);
        std::println(stderr, "{}", COLOR_RESET);
        return false;
    }

    std::println("{}", COLOR_YELLOW);
    std::println("WARNING: Formatting {} (Disk Name: {}) to APFS will ERASE ALL DATA. This cannot be undone!", device_path, disk_name);
    std::println("{}", COLOR_RESET);
    std::println("Selected device: {} ({})", disk_name, device_path);
    std::print("{}Type the Device Path ({}) to confirm (or type 'cancel' to return): {}", COLOR_CYAN, device_path, COLOR_RESET);
    std::string confirm_path;
    std::getline(std::cin, confirm_path);
    if (confirm_path == "cancel") {
        std::println("{}Formatting cancelled.{}", COLOR_CYAN, COLOR_RESET);
        return false;
    }
    if (confirm_path != device_path) {
        std::println(stderr, "{}Device Path mismatch. Formatting cancelled.{}", COLOR_RED, COLOR_RESET);
        return false;
    }

    std::print("{}Type 'YES' to confirm formatting (or type 'cancel' to return): {}", COLOR_CYAN, COLOR_RESET);
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm == "cancel") {
        std::println("{}Formatting cancelled.{}", COLOR_CYAN, COLOR_RESET);
        return false;
    }
    if (confirm != "YES") {
        std::println(stderr, "{}Formatting cancelled.{}", COLOR_RED, COLOR_RESET);
        return false;
    }

    // Unmount disk
    std::string command = std::format("diskutil unmountDisk {}", shell_quote(device_path));
    if (std::system(command.c_str()) != 0) {
        std::println(stderr, "{}Failed to unmount disk: {}.{}", COLOR_RED, device_path, COLOR_RESET);
        return false;
    }

    // Erase and format disk to APFS
    command = std::format("diskutil eraseDisk APFS {} {}", shell_quote(drive_name), shell_quote(device_path));
    if (std::system(command.c_str()) != 0) {
        std::println(stderr, "{}Failed to erase disk: {}.{}", COLOR_RED, device_path, COLOR_RESET);
        return false;
    }

    // Delay to ensure filesystem is ready
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Get full diskutil list output for debug
    command = "diskutil list";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::println(stderr, "{}Failed to execute diskutil list.{}", COLOR_RED, COLOR_RESET);
        return false;
    }
    char buffer[256];
    std::string full_list_output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        full_list_output += buffer;
    }
    pclose(pipe);

    // Find APFS container ID
    std::string device_id = device_path.substr(device_path.find_last_of('/') + 1); // Extract disk6 from /dev/disk6
    if (!std::regex_match(device_id, std::regex(R"(^disk[0-9]+$)"))) {
        std::println(stderr, "{}Error: Unexpected device id {}.{}", COLOR_RED, device_id, COLOR_RESET);
        return false;
    }
    command = std::format("diskutil list | grep 'Apple_APFS Container' | grep {}s2 | awk '{{print $4}}'", device_id);
    pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::println(stderr, "{}Failed to list APFS containers for {}.{}", COLOR_RED, device_path, COLOR_RESET);
        return false;
    }
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    trim_trailing_newlines(result);
    std::string container_id = result.empty() ? "" : "/dev/" + result;
    if (container_id.empty()) {
        std::println(stderr, "{}Error: Failed to find APFS container device. Full diskutil list output:\n{}", COLOR_RED, full_list_output, COLOR_RESET);
        return false;
    }

    // Find mount path
    command = std::format("diskutil apfs list {} | grep 'Mount Point' | awk '{{print $4}}' | head -n 1", shell_quote(container_id));
    pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::println(stderr, "{}Error: Failed to find mount point for {}.{}", COLOR_RED, container_id, COLOR_RESET);
        return false;
    }
    result.clear();
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result = buffer;
        trim_trailing_newlines(result);
    }
    pclose(pipe);
    output_path = result.empty() ? "/Volumes/" + drive_name : result;
    std::filesystem::path output_dir(output_path);
    if (!std::filesystem::exists(output_dir) || !std::filesystem::is_directory(output_dir)) {
        std::println(stderr, "{}Error: Mount path {} not found. Please mount the volume manually.{}", COLOR_RED, output_path, COLOR_RESET);
        return false;
    }

    std::println("{}", COLOR_GREEN);
    std::println("USB drive formatted successfully as {} (APFS). Your digital vault is ready! 🔒", drive_name);
    std::println("{}", COLOR_RESET);
    if (!store_key_in_blockchain(device_path, password, password, output_path)) {
        std::println(stderr, "{}Error: Failed to initialize vault key metadata on formatted drive.{}", COLOR_RED, COLOR_RESET);
        return false;
    }
    return true;
}

// Metadata structure for wallets
struct WalletMetadata {
    std::string wallet_id;
    std::string name;
    std::string currency;
    std::string file;
    std::string created_at;
};

// Save an existing wallet
void save_wallet(const std::string& wallet_id, const std::string& private_key, const std::string& seed_phrase,
                 const std::string& name, const std::string& currency, const std::string& output_path,
                 const std::string& password, const std::string& device_path) {
    (void)device_path;
    if (!is_valid_wallet_id(wallet_id)) {
        std::println(stderr, "{}Error: Invalid wallet ID '{}'. Use letters, numbers, underscore, dash (max 64).{}",
                     COLOR_RED, wallet_id, COLOR_RESET);
        return;
    }
    std::filesystem::path output_dir(output_path);
    if (!std::filesystem::exists(output_dir)) {
        std::println(stderr, "{}Error: Output directory does not exist: {}. Ensure the USB drive is mounted (e.g., /Volumes/VAULT) and the path is correct.{}", COLOR_RED, output_path, COLOR_RESET);
        return;
    }
    if (!std::filesystem::is_directory(output_dir) || !is_writable(output_dir)) {
        std::println(stderr, "{}Error: Cannot write to output directory: {}. Check permissions or mount the USB drive correctly.{}", COLOR_RED, output_path, COLOR_RESET);
        return;
    }

    std::stringstream wallet_data;
    wallet_data << std::format("wallet_id:{}\n", wallet_id);
    wallet_data << std::format("private_key:{}\n", private_key);
    wallet_data << std::format("seed_phrase:{}\n", seed_phrase);
    std::string wallet_str = wallet_data.str();

    auto salt = crypto::generate_salt();
    auto key = crypto::derive_key(password, salt);
    auto encrypted = crypto::encrypt(wallet_str, key);
    std::string wallet_file = output_path + "/wallet_" + wallet_id + ".dat";
    file::save(wallet_file, salt, encrypted);
    crypto::secure_zero(key.data(), key.size());
    secure_zero_string(wallet_str);

    std::string index_file = output_path + "/vault_index.dat";
    std::vector<WalletMetadata> index_data;
    if (std::filesystem::exists(index_file)) {
        try {
            auto [loaded_salt, loaded_encrypted] = file::load(index_file);
            auto loaded_key = crypto::derive_key(password, loaded_salt);
            std::string decrypted_index = crypto::decrypt(loaded_encrypted, loaded_key);
            std::istringstream iss(decrypted_index);
            std::string line;
            while (std::getline(iss, line)) {
                if (line.empty()) continue;
                std::vector<std::string> fields;
                std::stringstream ss(line);
                std::string field;
                while (std::getline(ss, field, '|')) {
                    fields.push_back(field);
                }
                if (fields.size() == 5) {
                    WalletMetadata metadata;
                    metadata.wallet_id = fields[0].substr(fields[0].find(':') + 1);
                    metadata.name = fields[1].substr(fields[1].find(':') + 1);
                    metadata.currency = fields[2].substr(fields[2].find(':') + 1);
                    metadata.file = fields[3].substr(fields[3].find(':') + 1);
                    metadata.created_at = fields[4].substr(fields[4].find(':') + 1);
                    index_data.push_back(metadata);
                }
            }
            crypto::secure_zero(loaded_key.data(), loaded_key.size());
            secure_zero_string(decrypted_index);
        } catch (const std::exception& e) {
            std::println(stderr, "{}Error: Failed to load or decrypt index file: {}. Ensure the correct password is used.{}", COLOR_RED, e.what(), COLOR_RESET);
            return;
        }
    }

    WalletMetadata metadata;
    metadata.wallet_id = wallet_id;
    metadata.name = name;
    metadata.currency = currency;
    metadata.file = "wallet_" + wallet_id + ".dat";
    metadata.created_at = std::to_string(std::time(nullptr));
    index_data.push_back(metadata);

    std::stringstream index_ss;
    for (const auto& item : index_data) {
        index_ss << std::format("wallet_id:{}|name:{}|currency:{}|file:{}|created_at:{}\n",
                                item.wallet_id, item.name, item.currency, item.file, item.created_at);
    }
    std::string index_str = index_ss.str();
    auto index_salt = crypto::generate_salt();
    auto index_key = crypto::derive_key(password, index_salt);
    auto index_encrypted = crypto::encrypt(index_str, index_key);
    file::save(index_file, index_salt, index_encrypted);
    crypto::secure_zero(index_key.data(), index_key.size());
    secure_zero_string(index_str);

    std::println("{}", COLOR_GREEN);
    std::println("Wallet {} saved to {}. Your digital vault is secure! 🔒", wallet_id, wallet_file);
    std::println("{}", COLOR_RESET);
    if (utils::is_debug_enabled()) {
        if (std::filesystem::exists(wallet_file) && std::filesystem::exists(index_file)) {
            std::println("{}Debug: Wallet file and index file successfully created.{}", COLOR_CYAN, COLOR_RESET);
        } else {
            std::println(stderr, "{}Debug: Failed to verify wallet file or index file creation.{}", COLOR_RED, COLOR_RESET);
        }
    }
}

// Recover stored wallets
void recover_wallet(const std::string& output_path, const std::string& password, const std::string& device_path) {
    (void)device_path;
    std::string recovered_password = recover_key_from_blockchain(output_path, password);
    if (recovered_password.empty()) {
        std::println("{}", COLOR_YELLOW);
        std::println("Warning: Failed to recover key from blockchain. Trying filesystem fallback.{}", COLOR_RESET);
        recovered_password = recover_key_from_filesystem(output_path, password);
    }
    if (recovered_password.empty()) {
        std::println(stderr, "{}Error: Failed to recover key from blockchain or filesystem. Please ensure the correct password is used and files exist.{}", COLOR_RED, COLOR_RESET);
        return;
    }
    if (!constant_time_equal(recovered_password, password)) {
        std::println(stderr, "{}Error: Recovered password does not match provided password.{}", COLOR_RED, COLOR_RESET);
        secure_zero_string(recovered_password);
        return;
    }
    secure_zero_string(recovered_password);

    std::string index_file = output_path + "/vault_index.dat";
    if (!std::filesystem::exists(index_file)) {
        std::println("{}No wallets found: Index file does not exist at {}. Please add a wallet first.{}", COLOR_RED, index_file, COLOR_RESET);
        return;
    }

    std::vector<WalletMetadata> wallets;
    try {
        auto [loaded_salt, loaded_encrypted] = file::load(index_file);
        auto loaded_key = crypto::derive_key(password, loaded_salt);
        std::string decrypted_index = crypto::decrypt(loaded_encrypted, loaded_key);
        std::istringstream iss(decrypted_index);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.empty()) continue;
            std::vector<std::string> fields;
            std::stringstream ss(line);
            std::string field;
            while (std::getline(ss, field, '|')) {
                fields.push_back(field);
            }
            if (fields.size() == 5) {
                WalletMetadata metadata;
                metadata.wallet_id = fields[0].substr(fields[0].find(':') + 1);
                metadata.name = fields[1].substr(fields[1].find(':') + 1);
                metadata.currency = fields[2].substr(fields[2].find(':') + 1);
                metadata.file = fields[3].substr(fields[3].find(':') + 1);
                metadata.created_at = fields[4].substr(fields[4].find(':') + 1);
                wallets.push_back(metadata);
            }
        }
        crypto::secure_zero(loaded_key.data(), loaded_key.size());
        secure_zero_string(decrypted_index);
    } catch (const std::exception& e) {
        std::println(stderr, "{}Error: Failed to decrypt or parse index file: {}. Please ensure the correct password is used.{}", COLOR_RED, e.what(), COLOR_RESET);
        return;
    }

    if (wallets.empty()) {
        std::println("{}No wallets found in index. Please add a wallet first.{}", COLOR_RED, COLOR_RESET);
        return;
    }

    std::println("Available wallets:");
    for (size_t i = 0; i < wallets.size(); ++i) {
        std::println("[{}] Wallet ID: {}, Name: {}, Currency: {}", i + 1, wallets[i].wallet_id, wallets[i].name, wallets[i].currency);
    }
    std::print("{}Select a wallet by number (1-{}) or type 'cancel' to return to main menu: {}", COLOR_CYAN, wallets.size(), COLOR_RESET);
    std::string choice;
    std::getline(std::cin, choice);
    if (choice == "cancel" || choice.empty()) {
        std::println("{}", COLOR_YELLOW);
        std::println("Wallet selection cancelled. Returning to main menu.{}", COLOR_RESET);
        return;
    }

    size_t wallet_index;
    try {
        wallet_index = std::stoul(choice);
        if (wallet_index < 1 || wallet_index > wallets.size()) {
            std::println("{}Invalid selection. Please select a number between 1 and {}.{}", COLOR_RED, wallets.size(), COLOR_RESET);
            return;
        }
    } catch (...) {
        std::println("{}Invalid input. Please enter a number or 'cancel'. Returning to main menu.{}", COLOR_RED, COLOR_RESET);
        return;
    }

    const auto& selected_wallet = wallets[wallet_index - 1];
    if (!is_valid_wallet_id(selected_wallet.wallet_id) || !is_safe_wallet_data_file(selected_wallet.file)) {
        std::println(stderr, "{}Error: Wallet metadata for selected entry is invalid or unsafe.{}", COLOR_RED, COLOR_RESET);
        return;
    }

    std::string expected_file = "wallet_" + selected_wallet.wallet_id + ".dat";
    if (selected_wallet.file != expected_file) {
        std::println(stderr, "{}Error: Wallet index integrity check failed for wallet {}.{}", COLOR_RED, selected_wallet.wallet_id, COLOR_RESET);
        return;
    }

    std::filesystem::path wallet_file_path = std::filesystem::path(output_path) / expected_file;
    std::string wallet_file = wallet_file_path.string();
    try {
        auto [wallet_salt, wallet_encrypted] = file::load(wallet_file);
        auto wallet_key = crypto::derive_key(password, wallet_salt);
        std::string decrypted_wallet = crypto::decrypt(wallet_encrypted, wallet_key);
        std::string wallet_id, private_key, seed_phrase;
        std::istringstream wallet_ss(decrypted_wallet);
        std::string line;
        while (std::getline(wallet_ss, line)) {
            if (line.find("wallet_id:") == 0) {
                wallet_id = line.substr(10);
            } else if (line.find("private_key:") == 0) {
                private_key = line.substr(12);
            } else if (line.find("seed_phrase:") == 0) {
                seed_phrase = line.substr(12);
            }
        }
        crypto::secure_zero(wallet_key.data(), wallet_key.size());
        secure_zero_string(decrypted_wallet);

        std::println("Recovery output mode:");
        std::println("[1] Display once in terminal (no file)");
        std::println("[2] Export plaintext file (higher risk)");
        std::println("[3] Cancel");
        std::print("{}Select an option (1-3): {}", COLOR_CYAN, COLOR_RESET);
        std::string output_choice;
        std::getline(std::cin, output_choice);

        if (output_choice == "1") {
            std::println("{}", COLOR_YELLOW);
            std::println("Wallet ID: {}", wallet_id);
            std::println("Private Key: {}", private_key);
            std::println("Seed Phrase: {}", seed_phrase);
            std::println("Displayed once. No plaintext file was created.");
            std::println("{}", COLOR_RESET);
        } else if (output_choice == "2") {
            std::string output_file = output_path + "/decrypted_wallet_" + selected_wallet.wallet_id + ".txt";
            std::ofstream out_file(output_file, std::ios::out | std::ios::trunc);
            if (!out_file) {
                std::println(stderr, "{}Error: Failed to open file for writing: {}.{}", COLOR_RED, output_file, COLOR_RESET);
                secure_zero_string(wallet_id);
                secure_zero_string(private_key);
                secure_zero_string(seed_phrase);
                return;
            }
            out_file << std::format("Wallet ID: {}\n", wallet_id);
            out_file << std::format("Private Key: {}\n", private_key);
            out_file << std::format("Seed Phrase: {}\n", seed_phrase);
            out_file.flush();
            if (!out_file) {
                out_file.close();
                std::println(stderr, "{}Error: Failed while writing wallet data to {}.{}", COLOR_RED, output_file, COLOR_RESET);
                secure_zero_string(wallet_id);
                secure_zero_string(private_key);
                secure_zero_string(seed_phrase);
                return;
            }
            out_file.close();

            std::error_code permissions_error;
            std::filesystem::permissions(
                output_file,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                permissions_error);
            if (permissions_error) {
                std::println(stderr, "{}Warning: Failed to enforce strict permissions on {}: {}.{}",
                             COLOR_YELLOW, output_file, permissions_error.message(), COLOR_RESET);
            }

            std::println("{}", COLOR_GREEN);
            std::println("Decrypted data for {} saved to {}.", wallet_id, output_file);
            std::println("Treat this plaintext file as highly sensitive and delete it as soon as possible.");
            std::println("{}", COLOR_RESET);
        } else {
            std::println("{}", COLOR_YELLOW);
            std::println("Recovery output cancelled.");
            std::println("{}", COLOR_RESET);
            secure_zero_string(wallet_id);
            secure_zero_string(private_key);
            secure_zero_string(seed_phrase);
            return;
        }

        secure_zero_string(wallet_id);
        secure_zero_string(private_key);
        secure_zero_string(seed_phrase);
    } catch (const std::exception& e) {
        std::println(stderr, "{}Error: Failed to decrypt or parse wallet file: {}. Please ensure the correct password is used.{}", COLOR_RED, e.what(), COLOR_RESET);
        return;
    }
}

// Check if password is strong
bool is_strong_password(const std::string& password) {
    if (password.length() < 16) return false;
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }
    return has_upper && has_lower && has_digit && has_special;
}

// Generate a strong password
std::string generate_secure_password(size_t length = 20) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const size_t charset_size = sizeof(charset) - 1;
    std::string password;
    password.reserve(length);
    std::vector<unsigned char> random_bytes(length);
    randombytes_buf(random_bytes.data(), length);
    std::string charset_str(charset, charset_size);
    password += charset_str[random_bytes[0] % 26];
    password += charset_str[26 + (random_bytes[1] % 26)];
    password += charset_str[52 + (random_bytes[2] % 10)];
    password += charset_str[62 + (random_bytes[3] % (charset_size - 62))];
    for (size_t i = 4; i < length; ++i) {
        password += charset_str[random_bytes[i] % charset_size];
    }
    for (size_t i = password.length(); i > 1; --i) {
        size_t j = random_bytes[i - 1] % i;
        std::swap(password[i - 1], password[j]);
    }
    return password;
}

// Scan mount paths for configured USB drive
bool find_existing_usb(std::string& output_path, std::string& password, std::string& device_path) {
#ifdef __APPLE__
    std::filesystem::path volumes_dir("/Volumes");
    if (!std::filesystem::exists(volumes_dir) || !std::filesystem::is_directory(volumes_dir)) {
        return false;
    }

    for (const auto& entry : std::filesystem::directory_iterator(volumes_dir)) {
        if (!entry.is_directory()) continue;
        std::filesystem::path index_file = entry.path() / "vault_index.dat";
        if (std::filesystem::exists(index_file) && is_writable(entry.path())) {
            output_path = entry.path().string();
            std::println("Found configured USB drive at {}", output_path);
            std::print("{}Enter the password for this USB drive (or type 'cancel' to return): {}", COLOR_CYAN, COLOR_RESET);
            password = get_secure_input("");
            if (password == "cancel") {
                return false;
            }
            if (password.empty()) {
                std::println("{}Password cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                return false;
            }
            try {
                auto [loaded_salt, loaded_encrypted] = file::load(index_file.string());
                auto loaded_key = crypto::derive_key(password, loaded_salt);
                std::string decrypted_index = crypto::decrypt(loaded_encrypted, loaded_key);
                crypto::secure_zero(loaded_key.data(), loaded_key.size());
                secure_zero_string(decrypted_index);
                device_path = output_path; // Use output_path for file-based sectors
                return true;
            } catch (const std::exception& e) {
                std::println(stderr, "{}Error: Invalid password for {}: {}.{}", COLOR_RED, output_path, e.what(), COLOR_RESET);
                return false;
            }
        }
    }
#endif
    return false;
}

// Get valid mount path with case-insensitive check
std::string get_mount_path(const std::string& suggested_name) {
#ifdef __APPLE__
    std::filesystem::path volumes_dir("/Volumes");
    if (!std::filesystem::exists(volumes_dir) || !std::filesystem::is_directory(volumes_dir)) {
        return "";
    }
    std::string lower_suggested_name = suggested_name;
    std::transform(lower_suggested_name.begin(), lower_suggested_name.end(), lower_suggested_name.begin(), ::tolower);
    for (const auto& entry : std::filesystem::directory_iterator(volumes_dir)) {
        if (!entry.is_directory()) continue;
        std::string entry_name = entry.path().filename().string();
        std::string lower_entry_name = entry_name;
        std::transform(lower_entry_name.begin(), lower_entry_name.end(), lower_entry_name.begin(), ::tolower);
        if (lower_entry_name == lower_suggested_name) {
            return entry.path().string();
        }
    }
    return "";
#else
    return "";
#endif
}

// Select or format USB drive
bool select_or_format_usb(std::string& output_path, std::string& password, std::string& device_path) {
    if (find_existing_usb(output_path, password, device_path)) {
        return true;
    }

    std::vector<UsbDevice> devices = list_usb_drives();
    if (devices.empty()) {
        std::println("{}ERROR: No USB drives detected. Press Enter to retry, or type 'cancel' to return:{}", COLOR_RED, COLOR_RESET);
        std::string retry;
        std::getline(std::cin, retry);
        if (retry == "cancel") {
            return false;
        }
        return select_or_format_usb(output_path, password, device_path);
    }

    std::println("Available USB drives:");
    for (size_t i = 0; i < devices.size(); ++i) {
        std::println("[{}] Path: {}, Disk Name: {}, Size: {}", i + 1, devices[i].path, devices[i].name, devices[i].size);
    }
    std::println("To find the correct Device Path, run 'diskutil list external' (macOS), 'lsblk' (Linux), or 'Get-Disk' (Windows) in a terminal.");
    std::println("Device Path is the path of the USB drive as shown in the list above (e.g., '/dev/disk6').");
    std::println("{}", COLOR_YELLOW);
    std::println("WARNING: Select the correct USB device to avoid formatting critical disks (e.g., system drive)!{}", COLOR_RESET);

    std::println("Select an option:");
    std::println("[1] Format a USB drive (erases all data)");
    std::println("[2] Use an existing USB drive");
    std::println("[3] Cancel and return to main menu");
    std::print("{}Select an option (1-3): {}", COLOR_CYAN, COLOR_RESET);
    std::string choice;
    std::getline(std::cin, choice);
    if (choice == "3" || choice == "cancel") {
        return false;
    }
    if (choice.empty()) {
        std::println("{}Invalid option. Please select a number between 1 and 3.{}", COLOR_RED, COLOR_RESET);
        return select_or_format_usb(output_path, password, device_path);
    }

    if (choice == "1") {
        password = generate_secure_password();
        std::println("{}", COLOR_GREEN);
        std::println("Generated password (copy exactly):");
        std::println("{}", password);
        std::println("Please save this password securely (e.g., in a password manager or physical safe)!{}", COLOR_RESET);
        std::print("{}If you prefer to use your own password, enter it now (at least 16 characters, including uppercase, lowercase, digits, and special characters), or press Enter to use the generated one (or type 'cancel' to return): {}", COLOR_CYAN, COLOR_RESET);
        std::string user_password = get_secure_input("");
        if (user_password == "cancel") {
            return false;
        }
        if (!user_password.empty()) {
            if (is_strong_password(user_password)) {
                password = user_password;
                std::println("{}", COLOR_GREEN);
                std::println("Custom password accepted. Please save it securely!{}", COLOR_RESET);
            } else {
                std::println("{}Warning: Provided password is not strong enough. Using generated password instead: {}{}", COLOR_YELLOW, password, COLOR_RESET);
            }
        }
        secure_zero_string(user_password);

        std::print("{}Select a USB drive by number (1-{}) or type 'cancel' to return: {}", COLOR_CYAN, devices.size(), COLOR_RESET);
        std::string device_choice;
        std::getline(std::cin, device_choice);
        if (device_choice == "cancel") {
            return false;
        }
        if (device_choice.empty()) {
            std::println("{}Invalid selection. Please select a number between 1 and {}.{}", COLOR_RED, devices.size(), COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        size_t device_index;
        try {
            device_index = std::stoul(device_choice);
            if (device_index < 1 || device_index > devices.size()) {
                std::println("{}Invalid selection. Please select a number between 1 and {}.{}", COLOR_RED, devices.size(), COLOR_RESET);
                return select_or_format_usb(output_path, password, device_path);
            }
        } catch (...) {
            std::println("{}Invalid input. Please enter a number or 'cancel'.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        UsbDevice selected_device = devices[device_index - 1];
        std::string format_device_path = selected_device.path; // Use device path for formatting
        std::string disk_name = selected_device.name;
        std::print("{}Enter a new name for the USB drive (e.g., Cpz) or type 'cancel' to return: {}", COLOR_CYAN, COLOR_RESET);
        std::string drive_name = get_secure_input("");
        if (drive_name == "cancel") {
            return false;
        }
        if (drive_name.empty()) {
            std::println("{}Drive name cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        device_path = "/Volumes/" + drive_name; // Use mount path for file-based sectors
        if (format_usb_drive(format_device_path, drive_name, disk_name, password, output_path)) {
            return true;
        } else {
            std::println("{}Formatting failed. Please try again.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
    } else if (choice == "2") {
        std::print("{}Select a USB drive by number (1-{}) or type 'cancel' to return: {}", COLOR_CYAN, devices.size(), COLOR_RESET);
        std::string device_choice;
        std::getline(std::cin, device_choice);
        if (device_choice == "cancel") {
            return false;
        }
        if (device_choice.empty()) {
            std::println("{}Invalid selection. Please select a number between 1 and {}.{}", COLOR_RED, devices.size(), COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        size_t device_index;
        try {
            device_index = std::stoul(device_choice);
            if (device_index < 1 || device_index > devices.size()) {
                std::println("{}Invalid selection. Please select a number between 1 and {}.{}", COLOR_RED, devices.size(), COLOR_RESET);
                return select_or_format_usb(output_path, password, device_path);
            }
        } catch (...) {
            std::println("{}Invalid input. Please enter a number or 'cancel'.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        UsbDevice selected_device = devices[device_index - 1];
        std::string disk_name = selected_device.name;
        std::string suggested_path = get_mount_path(disk_name);
        if (suggested_path.empty()) suggested_path = "/Volumes/VAULT";
#ifdef __APPLE__
        std::print("{}Enter mount path for existing USB (e.g., {}) or type 'cancel' to return: {}", COLOR_CYAN, suggested_path, COLOR_RESET);
        output_path = get_secure_input("");
#else
        std::print("{}Enter mount path for existing USB (e.g., /mnt/{} or D:\\) or type 'cancel' to return: {}", COLOR_CYAN, disk_name, COLOR_RESET);
        output_path = get_secure_input("");
#endif
        if (output_path == "cancel") {
            return false;
        }
        if (output_path.empty()) {
            std::println("{}Mount path cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        device_path = output_path; // Use output_path for file-based sectors
        std::print("{}Enter the password for this USB drive (or type 'cancel' to return): {}", COLOR_CYAN, COLOR_RESET);
        password = get_secure_input("");
        if (password == "cancel") {
            return false;
        }
        if (password.empty()) {
            std::println("{}Password cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        std::string recovered_password = recover_key_from_blockchain(device_path, password);
        if (recovered_password.empty()) {
            std::println("{}", COLOR_YELLOW);
            std::println("Warning: Failed to recover key from blockchain. Trying filesystem fallback.{}", COLOR_RESET);
            recovered_password = recover_key_from_filesystem(output_path, password);
        }
        if (recovered_password.empty()) {
            std::println(stderr, "{}Error: Failed to recover key from blockchain or filesystem. Please ensure the correct password is used and files exist.{}", COLOR_RED, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        if (!constant_time_equal(recovered_password, password)) {
            secure_zero_string(recovered_password);
            std::println(stderr, "{}Error: Invalid password for {}.{}", COLOR_RED, output_path, COLOR_RESET);
            return select_or_format_usb(output_path, password, device_path);
        }
        secure_zero_string(recovered_password);
    } else {
        std::println("{}Invalid option. Please select a number between 1 and 3.{}", COLOR_RED, COLOR_RESET);
        return select_or_format_usb(output_path, password, device_path);
    }

    std::filesystem::path output_dir(output_path);
    if (!std::filesystem::exists(output_dir)) {
        std::println(stderr, "{}Error: Output directory does not exist: {}. Ensure the USB drive is mounted (e.g., /Volumes/VAULT) and the path is correct.{}", COLOR_RED, output_path, COLOR_RESET);
        return false;
    }
    if (!std::filesystem::is_directory(output_dir) || !is_writable(output_dir)) {
        std::println(stderr, "{}Error: Cannot write to output directory: {}. Check permissions or mount the USB drive correctly.{}", COLOR_RED, output_path, COLOR_RESET);
        return false;
    }

    return true;
}

void run() {
    crypto::initialize();

    display_banner();

    std::string output_path;
    std::string password;
    std::string device_path;
    bool usb_ready = false;

    if (find_existing_usb(output_path, password, device_path)) {
        usb_ready = true;
    }

    while (true) {
        if (usb_ready && !output_path.empty()) {
            std::filesystem::path output_dir(output_path);
            if (!std::filesystem::exists(output_dir) || !std::filesystem::is_directory(output_dir) || !is_writable(output_dir)) {
                std::println(stderr, "{}Error: USB drive at {} is no longer accessible. Please reconfigure USB drive.{}", COLOR_RED, output_path, COLOR_RESET);
                usb_ready = false;
                output_path.clear();
                secure_zero_string(password);
                device_path.clear();
                continue;
            }

            std::println("\nVaultGuard Menu (USB ready at {}):", output_path);
            std::println("[1] Store an existing wallet");
            std::println("[2] Recover stored wallets");
            std::println("[3] Change USB drive");
            std::println("[4] Exit");
            std::print("{}Select an option (1-4): {}", COLOR_CYAN, COLOR_RESET);
            std::fflush(stdout);
            std::string menu_choice;
            std::getline(std::cin, menu_choice);
            trim_trailing_newlines(menu_choice);
            std::println("");
            if (menu_choice.empty()) {
                std::println("{}Invalid option. Please select a number between 1 and 4.{}", COLOR_RED, COLOR_RESET);
                continue;
            }

            if (menu_choice == "4") {
                std::println("{}Program terminated.{}", COLOR_CYAN, COLOR_RESET);
                break;
            }
            if (menu_choice == "1") {
                std::println("Store Wallet Menu:");
                std::println("[1] Enter wallet manually");
                std::println("[2] Read from file");
                std::println("[3] Cancel and return to main menu");
                std::print("{}Select an option (1-3): {}", COLOR_CYAN, COLOR_RESET);
                std::fflush(stdout);
                std::string wallet_choice;
                std::getline(std::cin, wallet_choice);
                trim_trailing_newlines(wallet_choice);
                std::println("");
                if (wallet_choice == "3" || wallet_choice == "cancel") {
                    continue;
                }
                if (wallet_choice.empty()) {
                    std::println("{}Invalid option. Please select a number between 1 and 3.{}", COLOR_RED, COLOR_RESET);
                    continue;
                }

                std::string wallet_id = get_secure_input("Enter unique wallet ID (e.g., Bitcoin_Wallet_1) or type 'cancel' to return");
                if (wallet_id == "cancel") {
                    continue;
                }
                if (wallet_id.empty()) {
                    std::println("{}Wallet ID cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                    continue;
                }
                if (!is_valid_wallet_id(wallet_id)) {
                    std::println("{}Invalid wallet ID format. Use letters, numbers, '_' or '-' only (max 64).{}", COLOR_RED, COLOR_RESET);
                    continue;
                }
                std::string name = get_secure_input("Enter wallet name (e.g., My BTC Wallet, GENY Wallet) or type 'cancel' to return");
                if (name == "cancel") {
                    continue;
                }
                if (name.empty()) {
                    std::println("{}Wallet name cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                    continue;
                }
                std::string currency = get_secure_input("Enter currency (e.g., BTC, ETH, GENY) or type 'cancel' to return");
                if (currency == "cancel") {
                    continue;
                }
                if (currency.empty()) {
                    std::println("{}Currency cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                    continue;
                }
                std::string private_key, seed_phrase;

                if (wallet_choice == "1") {
                    private_key = get_secure_input("Enter private key (or type 'cancel' to return)");
                    if (private_key == "cancel") {
                        continue;
                    }
                    if (private_key.empty()) {
                        std::println("{}Private key cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                        continue;
                    }
                    seed_phrase = get_secure_input("Enter seed phrase (or type 'cancel' to return)");
                    if (seed_phrase == "cancel") {
                        continue;
                    }
                    if (seed_phrase.empty()) {
                        std::println("{}Seed phrase cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                        continue;
                    }
                } else if (wallet_choice == "2") {
                    std::string file_path = get_secure_input("Enter path to file containing private key and seed phrase (one per line) or type 'cancel' to return");
                    if (file_path == "cancel") {
                        continue;
                    }
                    if (file_path.empty()) {
                        std::println("{}File path cannot be empty. Please try again.{}", COLOR_RED, COLOR_RESET);
                        continue;
                    }
                    try {
                        std::string file_content = read_from_file(file_path);
                        size_t pos = file_content.find('\n');
                        if (pos == std::string::npos) {
                            std::println(stderr, "{}Error: Invalid file format: expected private key and seed phrase on separate lines{}", COLOR_RED, COLOR_RESET);
                            continue;
                        }
                        private_key = file_content.substr(0, pos);
                        seed_phrase = file_content.substr(pos + 1);
                        if (private_key.empty() || seed_phrase.empty()) {
                            std::println(stderr, "{}Error: Private key or seed phrase is empty in file{}", COLOR_RED, COLOR_RESET);
                            secure_zero_string(file_content);
                            continue;
                        }
                        secure_zero_string(file_content);
                    } catch (const std::exception& e) {
                        std::println(stderr, "{}Error: Failed to read file: {}", COLOR_RED, e.what());
                        std::println(stderr, "{}", COLOR_RESET);
                        continue;
                    }
                } else {
                    std::println("{}Invalid option. Please select a number between 1 and 3.{}", COLOR_RED, COLOR_RESET);
                    continue;
                }

                save_wallet(wallet_id, private_key, seed_phrase, name, currency, output_path, password, device_path);
                secure_zero_string(private_key);
                secure_zero_string(seed_phrase);
            } else if (menu_choice == "2") {
                recover_wallet(output_path, password, device_path);
            } else if (menu_choice == "3") {
                usb_ready = false;
                output_path.clear();
                secure_zero_string(password);
                device_path.clear();
            } else {
                std::println("{}Invalid option. Please select a number between 1 and 4.{}", COLOR_RED, COLOR_RESET);
            }
        } else {
            std::println("\nVaultGuard Menu (No USB drive configured):");
            std::println("[1] Prepare USB drive");
            std::println("[2] Exit");
            std::print("{}Select an option (1-2): {}", COLOR_CYAN, COLOR_RESET);
            std::fflush(stdout);
            std::string menu_choice;
            std::getline(std::cin, menu_choice);
            trim_trailing_newlines(menu_choice);
            std::println("");
            if (menu_choice.empty()) {
                std::println("{}Invalid option. Please select a number between 1 and 2.{}", COLOR_RED, COLOR_RESET);
                continue;
            }

            if (menu_choice == "2" || menu_choice == "cancel") {
                std::println("{}Program terminated.{}", COLOR_CYAN, COLOR_RESET);
                break;
            }
            if (menu_choice == "1") {
                if (select_or_format_usb(output_path, password, device_path)) {
                    usb_ready = true;
                }
            } else {
                std::println("{}Invalid option. Please select a number between 1 and 2.{}", COLOR_RED, COLOR_RESET);
            }
        }
    }

    secure_zero_string(password);
}

} // namespace vaultguard::wallet
