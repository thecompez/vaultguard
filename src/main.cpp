import wallet;
import <iostream>;
import <exception>;

auto main() ->int {
    try {
        vaultguard::wallet::run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}