import crypto;
import file;
import wallet;

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

int main() {
    vaultguard::crypto::initialize();

    assert(vaultguard::wallet::is_valid_wallet_id("Wallet_1-OK"));
    assert(vaultguard::wallet::is_valid_wallet_id("wallet-2026"));
    assert(!vaultguard::wallet::is_valid_wallet_id("wallet.with.dot"));
    assert(!vaultguard::wallet::is_valid_wallet_id("../wallet"));
    assert(!vaultguard::wallet::is_valid_wallet_id("wallet/name"));

    assert(vaultguard::wallet::constant_time_equal("secret", "secret"));
    assert(!vaultguard::wallet::constant_time_equal("secret", "secreT"));
    assert(!vaultguard::wallet::constant_time_equal("short", "longer"));

    std::error_code ec;
    const std::filesystem::path test_root = std::filesystem::temp_directory_path() / "vaultguard_security_tests";
    std::filesystem::remove_all(test_root, ec);
    ec.clear();
    std::filesystem::create_directories(test_root, ec);
    assert(!ec);

    const std::vector<unsigned char> salt = vaultguard::crypto::generate_salt();
    const std::vector<unsigned char> encrypted = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};

    const std::string modern_file = (test_root / "modern_wallet.dat").string();
    vaultguard::file::save(modern_file, salt, encrypted);
    const auto [modern_salt, modern_encrypted] = vaultguard::file::load(modern_file);
    assert(modern_salt == salt);
    assert(modern_encrypted == encrypted);

    const std::string legacy_file = (test_root / "legacy_wallet.dat").string();
    {
        std::ofstream out(legacy_file, std::ios::binary | std::ios::trunc);
        assert(out);
        out.write(reinterpret_cast<const char*>(salt.data()), static_cast<std::streamsize>(salt.size()));
        out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
        out.flush();
        assert(out.good());
    }
    const auto [legacy_salt, legacy_encrypted] = vaultguard::file::load(legacy_file);
    assert(legacy_salt == salt);
    assert(legacy_encrypted == encrypted);

    const std::string password = "A_Strong_Test_Password#2026";
    const bool stored = vaultguard::wallet::store_key_in_blockchain(test_root.string(), password, password, test_root.string());
    assert(stored);

    const std::string recovered = vaultguard::wallet::recover_key_from_blockchain(test_root.string(), password);
    assert(vaultguard::wallet::constant_time_equal(recovered, password));

    const std::string wrong_password_recovery = vaultguard::wallet::recover_key_from_blockchain(test_root.string(), "wrong-password");
    assert(wrong_password_recovery.empty());

    std::filesystem::remove_all(test_root, ec);
    std::cout << "vaultguard_tests passed\n";
    return 0;
}
