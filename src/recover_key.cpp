import wallet;
import crypto;

#include <exception>
#include <format>
#include <iostream>
#include <string>

namespace {
void secure_zero_string(std::string& value) {
    if (!value.empty()) {
        vaultguard::crypto::secure_zero(value.data(), value.size());
        value.clear();
    }
}
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << std::format("Usage: {} <mount_path> [--show-key]", argv[0]) << '\n';
        return 1;
    }

    bool show_key = false;
    if (argc == 3) {
        const std::string option = argv[2];
        if (option != "--show-key") {
            std::cerr << std::format("Unknown option: {}", option) << '\n';
            std::cerr << std::format("Usage: {} <mount_path> [--show-key]", argv[0]) << '\n';
            return 1;
        }
        show_key = true;
    }

    try {
        vaultguard::crypto::initialize();

        const std::string mount_path = argv[1];
        std::string password = vaultguard::wallet::get_secure_input("Enter password");
        if (password.empty() || password == "cancel") {
            secure_zero_string(password);
            std::cerr << "Password cannot be empty.\n";
            return 1;
        }

        std::string recovered_key = vaultguard::wallet::recover_key_from_blockchain(mount_path, password);
        if (recovered_key.empty()) {
            recovered_key = vaultguard::wallet::recover_key_from_filesystem(mount_path, password);
        }

        if (recovered_key.empty()) {
            std::cerr << "Failed to recover key. Check mount path, password, and vault files.\n";
            secure_zero_string(password);
            return 1;
        }

        if (!vaultguard::wallet::constant_time_equal(recovered_key, password)) {
            std::cerr << "Recovered key validation failed.\n";
            secure_zero_string(recovered_key);
            secure_zero_string(password);
            return 1;
        }

        if (show_key) {
            std::cout << std::format("Recovered key: {}", recovered_key) << '\n';
        } else {
            std::cout << "Key recovered successfully.\n";
            std::cout << "Use --show-key if you need to print it.\n";
        }

        secure_zero_string(recovered_key);
        secure_zero_string(password);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << std::format("Error: {}", e.what()) << '\n';
        return 1;
    }
}
