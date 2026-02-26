import crypto;
import file;
import wallet;

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace {
bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}
}

int main() {
    vaultguard::crypto::initialize();

    std::error_code ec;
    const auto tick = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    const std::filesystem::path test_root =
        std::filesystem::temp_directory_path() / ("vaultguard_integration_tests_" + std::to_string(tick));
    std::filesystem::remove_all(test_root, ec);
    ec.clear();
    std::filesystem::create_directories(test_root, ec);
    assert(!ec);

    const std::string password = "A_Strong_Integration_Password#2026";
    const std::string device_path = test_root.string();

    const bool stored = vaultguard::wallet::store_key_in_blockchain(device_path, password, password, test_root.string());
    assert(stored);

    const std::string recovered = vaultguard::wallet::recover_key_from_blockchain(device_path, password);
    assert(vaultguard::wallet::constant_time_equal(recovered, password));
    const std::string wrong_recovery = vaultguard::wallet::recover_key_from_blockchain(device_path, "wrong-password");
    assert(wrong_recovery.empty());

    vaultguard::wallet::save_wallet("WalletOne", "pk-1", "seed one two three",
                                    "Primary Wallet", "BTC", test_root.string(), password, device_path);
    vaultguard::wallet::save_wallet("WalletTwo", "pk-2", "seed four five six",
                                    "Secondary Wallet", "ETH", test_root.string(), password, device_path);
    vaultguard::wallet::save_wallet("bad.id", "pk-invalid", "seed invalid",
                                    "Invalid Wallet", "DOGE", test_root.string(), password, device_path);

    assert(std::filesystem::exists(test_root / "wallet_WalletOne.dat"));
    assert(std::filesystem::exists(test_root / "wallet_WalletTwo.dat"));
    assert(!std::filesystem::exists(test_root / "wallet_bad.id.dat"));

    const std::filesystem::path index_path = test_root / "vault_index.dat";
    assert(std::filesystem::exists(index_path));
    {
        const auto [index_salt, index_encrypted] = vaultguard::file::load(index_path.string());
        auto index_key = vaultguard::crypto::derive_key(password, index_salt);
        std::string decrypted_index = vaultguard::crypto::decrypt(index_encrypted, index_key);
        vaultguard::crypto::secure_zero(index_key.data(), index_key.size());

        assert(contains(decrypted_index, "wallet_id:WalletOne"));
        assert(contains(decrypted_index, "file:wallet_WalletOne.dat"));
        assert(contains(decrypted_index, "wallet_id:WalletTwo"));
        assert(contains(decrypted_index, "file:wallet_WalletTwo.dat"));
        assert(!contains(decrypted_index, "wallet_id:bad.id"));

        vaultguard::crypto::secure_zero(decrypted_index.data(), decrypted_index.size());
        decrypted_index.clear();
    }

    const std::vector<std::tuple<std::string, std::string, std::string>> expected_wallets = {
        {"WalletOne", "private_key:pk-1", "seed_phrase:seed one two three"},
        {"WalletTwo", "private_key:pk-2", "seed_phrase:seed four five six"}
    };

    for (const auto& [wallet_id, private_key_line, seed_phrase_line] : expected_wallets) {
        const std::filesystem::path wallet_path = test_root / ("wallet_" + wallet_id + ".dat");
        assert(std::filesystem::exists(wallet_path));

        const auto [wallet_salt, wallet_encrypted] = vaultguard::file::load(wallet_path.string());
        auto wallet_key = vaultguard::crypto::derive_key(password, wallet_salt);
        std::string decrypted_wallet = vaultguard::crypto::decrypt(wallet_encrypted, wallet_key);
        vaultguard::crypto::secure_zero(wallet_key.data(), wallet_key.size());

        assert(contains(decrypted_wallet, "wallet_id:" + wallet_id));
        assert(contains(decrypted_wallet, private_key_line));
        assert(contains(decrypted_wallet, seed_phrase_line));

        vaultguard::crypto::secure_zero(decrypted_wallet.data(), decrypted_wallet.size());
        decrypted_wallet.clear();
    }

    std::filesystem::remove_all(test_root, ec);
    std::cout << "vaultguard_integration_tests passed\n";
    return 0;
}
