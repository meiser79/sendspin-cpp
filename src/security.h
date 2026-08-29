#pragma once

#ifndef ESP_PLATFORM

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

class SendspinPersistenceProvider;

enum class SendspinPskKind : uint8_t {
    SENTINEL,
    PAIRING,
    LONG_TERM,
};

struct SendspinPairingRecord {
    std::string server_id;  // empty for shared-PSK records
    std::array<uint8_t, 32> psk{};
    bool used{false};
};

enum class SendspinManagementResult : uint8_t {
    OK,
    PERMISSION_DENIED,
    ALREADY_EXISTS,
    INVALID,
    NOT_FOUND,
    STORAGE_EXHAUSTED,
};

class SendspinSecurityState {
public:
    explicit SendspinSecurityState(SendspinPersistenceProvider* persistence);

    bool initialize(bool default_unpaired_access = true);
    const std::array<uint8_t, 32>& private_key() const { return private_key_; }
    const std::array<uint8_t, 32>& public_key() const { return public_key_; }
    const std::array<uint8_t, 32>& pairing_psk() const { return pairing_psk_; }
    const std::string& client_id() const { return client_id_; }
    std::string pairing_token() const;

    bool find_psk(const std::string& psk_id, const std::string& server_id,
                  std::array<uint8_t, 32>& psk, SendspinPskKind& kind);
    bool add_record(const std::string& server_id, const std::array<uint8_t, 32>& psk);
    bool has_record_for_server(const std::string& server_id) const;

    const std::vector<SendspinPairingRecord>& records() const { return records_; }
    bool pairing_psk_enabled() const { return pairing_psk_enabled_; }
    bool unpaired_access_enabled() const { return unpaired_access_enabled_; }
    const std::string& record_mode_psk_id() const { return record_mode_psk_id_; }
    SendspinManagementResult add_management_record(const std::string& server_id,
                                                   const std::string& encoded_psk);
    SendspinManagementResult remove_management_record(const std::string& record_psk_id);
    SendspinManagementResult set_pairing_psk_enabled(bool enabled);
    SendspinManagementResult replace_pairing_psk(const std::string& encoded_psk);
    SendspinManagementResult set_unpaired_access(bool enabled);
    SendspinManagementResult set_record_mode(const std::string& record_psk_id);

    static std::string base64url_encode(const uint8_t* data, size_t len);
    static bool base64url_decode(const std::string& text, std::vector<uint8_t>& out);
    static std::string psk_id(const std::array<uint8_t, 32>& psk);
    static bool random_bytes(uint8_t* data, size_t len);

private:
    SendspinPersistenceProvider* persistence_{nullptr};
    std::array<uint8_t, 32> private_key_{};
    std::array<uint8_t, 32> public_key_{};
    std::array<uint8_t, 32> pairing_psk_{};
    std::vector<SendspinPairingRecord> records_;
    std::string client_id_;
    bool pairing_psk_enabled_{true};
    bool unpaired_access_enabled_{true};
    std::string record_mode_psk_id_;

    bool persist_security_value(const std::string& key, const std::string& value);
    bool load_bool_security_value(const std::string& key, bool fallback) const;
    bool is_reserved_psk_id(const std::string& id) const;
    bool mark_record_used(SendspinPairingRecord& record);
};

class NoiseResponderSession {
public:
    NoiseResponderSession();
    ~NoiseResponderSession();
    NoiseResponderSession(const NoiseResponderSession&) = delete;
    NoiseResponderSession& operator=(const NoiseResponderSession&) = delete;

    bool begin(const std::array<uint8_t, 32>& local_private,
               const std::array<uint8_t, 32>& local_public,
               const std::array<uint8_t, 32>& remote_public,
               const uint8_t* prologue, size_t prologue_len);

    bool read_message1(const uint8_t* message, size_t len, std::string& payload_json);
    bool write_message2(const std::array<uint8_t, 32>& psk, const std::string& payload_json,
                        std::vector<uint8_t>& out);

    bool encrypt(const uint8_t* plaintext, size_t len, std::vector<uint8_t>& ciphertext);
    bool decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext);

    const std::array<uint8_t, 32>& handshake_hash() const { return h_; }
    bool transport_ready() const { return transport_ready_; }

private:
    struct CipherState {
        std::array<uint8_t, 32> key{};
        uint64_t nonce{0};
        bool has_key{false};
    };

    bool mix_hash(const uint8_t* data, size_t len);
    bool mix_key(const uint8_t* data, size_t len);
    bool mix_key_and_hash(const uint8_t* data, size_t len);
    bool decrypt_and_hash(const uint8_t* data, size_t len, std::vector<uint8_t>& plaintext);
    bool encrypt_and_hash(const uint8_t* data, size_t len, std::vector<uint8_t>& ciphertext);
    bool dh(const std::array<uint8_t, 32>& priv, const std::array<uint8_t, 32>& pub,
            std::array<uint8_t, 32>& out) const;
    bool split();

    static bool sha256(const uint8_t* data, size_t len, std::array<uint8_t, 32>& out);
    static bool hkdf(const std::array<uint8_t, 32>& chaining_key, const uint8_t* input,
                     size_t input_len, size_t outputs,
                     std::array<std::array<uint8_t, 32>, 3>& out);
    static bool aead_encrypt(CipherState& cipher, const uint8_t* ad, size_t ad_len,
                             const uint8_t* plaintext, size_t plaintext_len,
                             std::vector<uint8_t>& ciphertext);
    static bool aead_decrypt(CipherState& cipher, const uint8_t* ad, size_t ad_len,
                             const uint8_t* ciphertext, size_t ciphertext_len,
                             std::vector<uint8_t>& plaintext);

    std::array<uint8_t, 32> local_private_{};
    std::array<uint8_t, 32> local_public_{};
    std::array<uint8_t, 32> remote_public_{};
    std::array<uint8_t, 32> remote_ephemeral_{};
    std::array<uint8_t, 32> local_ephemeral_private_{};
    std::array<uint8_t, 32> local_ephemeral_public_{};
    std::array<uint8_t, 32> ck_{};
    std::array<uint8_t, 32> h_{};
    CipherState handshake_cipher_{};
    CipherState receive_cipher_{};
    CipherState send_cipher_{};
    bool message1_read_{false};
    bool transport_ready_{false};
};

}  // namespace sendspin

#endif
