import wallet;
import crypto;

import <exception>;
import <iostream>;
import <print>;
import <string>;

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
        std::println(stderr, "Usage: {} <mount_path> [--show-key]", argv[0]);
        return 1;
    }

    bool show_key = false;
    if (argc == 3) {
        const std::string option = argv[2];
        if (option != "--show-key") {
            std::println(stderr, "Unknown option: {}", option);
            std::println(stderr, "Usage: {} <mount_path> [--show-key]", argv[0]);
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
            std::println(stderr, "Password cannot be empty.");
            return 1;
        }

        std::string recovered_key = vaultguard::wallet::recover_key_from_blockchain(mount_path, password);
        if (recovered_key.empty()) {
            recovered_key = vaultguard::wallet::recover_key_from_filesystem(mount_path, password);
        }

        if (recovered_key.empty()) {
            std::println(stderr, "Failed to recover key. Check mount path, password, and vault files.");
            secure_zero_string(password);
            return 1;
        }

        if (!vaultguard::wallet::constant_time_equal(recovered_key, password)) {
            std::println(stderr, "Recovered key validation failed.");
            secure_zero_string(recovered_key);
            secure_zero_string(password);
            return 1;
        }

        if (show_key) {
            std::println("Recovered key: {}", recovered_key);
        } else {
            std::println("Key recovered successfully.");
            std::println("Use --show-key if you need to print it.");
        }

        secure_zero_string(recovered_key);
        secure_zero_string(password);
        return 0;
    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }
}
