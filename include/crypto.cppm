module;

#include <sodium.h>

export module crypto;

import <vector>;
import <string>;
import <stdexcept>;
import <span>;

export namespace vaultguard::crypto {
void initialize() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(
            key.data(), key.size(),
            password.c_str(), password.size(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_SENSITIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Key derivation failed");
    }
    return key;
}

std::vector<unsigned char> encrypt(const std::string& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext(data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
            nullptr, 0, nullptr,
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }

    std::vector<unsigned char> result;
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    return result;
}

std::string decrypt(const std::vector<unsigned char>& encrypted, const std::vector<unsigned char>& key) {
    if (encrypted.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw std::runtime_error("Invalid encrypted data");
    }

    std::span<const unsigned char> nonce(encrypted.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::span<const unsigned char> ciphertext(encrypted.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                             encrypted.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("Decryption failed");
    }

    return std::string(decrypted.begin(), decrypted.begin() + decrypted_len);
}

std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

void secure_zero(void* data, size_t size) {
    sodium_memzero(data, size);
}

}
