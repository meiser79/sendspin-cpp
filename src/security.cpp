#ifndef ESP_PLATFORM

#include "security.h"

#include "sendspin/client.h"
#include "platform/logging.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace sendspin {
namespace {

static const char* const TAG = "sendspin.security";
constexpr char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr uint8_t SENTINEL_PSK_BYTES[32] = {
    0x1b,0x5e,0x24,0xdb,0xc1,0xae,0xd9,0x5f,0xc2,0xa5,0xa3,0x38,0xa9,0x0c,0x05,0xdf,
    0x44,0xbd,0x10,0xf5,0xec,0x1f,0x4c,0xd6,0x6c,0xbf,0x86,0x27,0x27,0x67,0xb9,0xd3};
constexpr char NOISE_NAME[] = "Noise_KKpsk2_25519_ChaChaPoly_SHA256";

std::string base32_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(BASE32_ALPHABET[(buffer >> bits) & 0x1f]);
        }
    }
    if (bits > 0) {
        out.push_back(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f]);
    }
    return out;
}

bool derive_public(const std::array<uint8_t, 32>& priv, std::array<uint8_t, 32>& pub) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    if (!key) return false;
    size_t len = pub.size();
    const bool ok = EVP_PKEY_get_raw_public_key(key, pub.data(), &len) == 1 && len == pub.size();
    EVP_PKEY_free(key);
    return ok;
}

}  // namespace

SendspinSecurityState::SendspinSecurityState(SendspinPersistenceProvider* persistence)
    : persistence_(persistence) {}

bool SendspinSecurityState::random_bytes(uint8_t* data, size_t len) {
    return RAND_bytes(data, static_cast<int>(len)) == 1;
}

std::string SendspinSecurityState::base64url_encode(const uint8_t* data, size_t len) {
    if (len == 0) return {};
    std::string out(((len + 2) / 3) * 4, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                                  static_cast<int>(len));
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    for (char& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

bool SendspinSecurityState::base64url_decode(const std::string& text, std::vector<uint8_t>& out) {
    std::string padded = text;
    for (char& c : padded) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (padded.size() % 4 != 0) padded.push_back('=');
    out.resize((padded.size() / 4) * 3);
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(padded.data()),
                                  static_cast<int>(padded.size()));
    if (n < 0) return false;
    size_t actual = static_cast<size_t>(n);
    if (!padded.empty() && padded.back() == '=') --actual;
    if (padded.size() > 1 && padded[padded.size() - 2] == '=') --actual;
    out.resize(actual);
    return true;
}

std::string SendspinSecurityState::psk_id(const std::array<uint8_t, 32>& psk) {
    static constexpr char LABEL[] = "sendspin-psk-id-v1";
    SHA256_CTX ctx;
    std::array<uint8_t, 32> digest{};
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, LABEL, sizeof(LABEL) - 1);
    SHA256_Update(&ctx, psk.data(), psk.size());
    SHA256_Final(digest.data(), &ctx);
    return base64url_encode(digest.data(), digest.size());
}

bool SendspinSecurityState::initialize(bool default_unpaired_access) {
    auto load32 = [](const std::optional<std::string>& encoded, std::array<uint8_t, 32>& target) {
        if (!encoded) return false;
        std::vector<uint8_t> raw;
        if (!base64url_decode(*encoded, raw) || raw.size() != target.size()) return false;
        std::copy(raw.begin(), raw.end(), target.begin());
        return true;
    };

    bool have_private = false;
    bool have_pairing = false;
    if (persistence_) {
        have_private = load32(persistence_->load_security_private_key(), private_key_);
        have_pairing = load32(persistence_->load_pairing_psk(), pairing_psk_);
    }
    if (!have_private) {
        if (!random_bytes(private_key_.data(), private_key_.size())) return false;
        if (persistence_ && !persistence_->save_security_private_key(
                                base64url_encode(private_key_.data(), private_key_.size()))) {
            SS_LOGW(TAG, "Could not persist security private key");
        }
    }
    if (!derive_public(private_key_, public_key_)) return false;
    client_id_ = base64url_encode(public_key_.data(), public_key_.size());

    if (!have_pairing) {
        if (!random_bytes(pairing_psk_.data(), pairing_psk_.size())) return false;
        if (persistence_ && !persistence_->save_pairing_psk(
                                base64url_encode(pairing_psk_.data(), pairing_psk_.size()))) {
            SS_LOGW(TAG, "Could not persist pairing PSK");
        }
    }

    pairing_psk_enabled_ = load_bool_security_value("management.pairing_psk_enabled", true);
    unpaired_access_enabled_ =
        load_bool_security_value("management.unpaired_access", default_unpaired_access);

    records_.clear();
    if (persistence_) {
        for (const auto& record : persistence_->load_pairing_records()) {
            std::vector<uint8_t> raw;
            if (base64url_decode(record.psk, raw) && raw.size() == 32 && !record.server_id.empty()) {
                SendspinPairingRecord converted;
                converted.server_id = record.server_id;
                std::copy(raw.begin(), raw.end(), converted.psk.begin());
                const std::string id = psk_id(converted.psk);
                if (persistence_->load_security_value("management.removed." + id).value_or("") == "1")
                    continue;
                converted.used =
                    persistence_->load_security_value("management.used." + id).value_or("") == "1";
                records_.push_back(std::move(converted));
            }
        }

        record_mode_psk_id_ =
            persistence_->load_security_value("management.record_mode_psk_id").value_or("");
        const std::string shared_ids =
            persistence_->load_security_value("management.shared_ids").value_or("");
        size_t begin = 0;
        while (begin < shared_ids.size()) {
            const size_t comma = shared_ids.find(',', begin);
            const std::string id = shared_ids.substr(
                begin, comma == std::string::npos ? std::string::npos : comma - begin);
            begin = comma == std::string::npos ? shared_ids.size() : comma + 1;
            if (id.empty() ||
                persistence_->load_security_value("management.removed." + id).value_or("") == "1")
                continue;
            const auto shared = persistence_->load_security_value("management.shared." + id);
            if (!shared.has_value()) continue;
            std::vector<uint8_t> raw;
            if (base64url_decode(*shared, raw) && raw.size() == 32) {
                SendspinPairingRecord converted;
                std::copy(raw.begin(), raw.end(), converted.psk.begin());
                converted.used = persistence_->load_security_value(
                    "management.used." + id).value_or("") == "1";
                records_.push_back(std::move(converted));
            }
        }
    }
    return true;
}

std::string SendspinSecurityState::pairing_token() const {
    if (!pairing_psk_enabled_) return {};
    std::array<uint8_t, 64> payload{};
    std::copy(public_key_.begin(), public_key_.end(), payload.begin());
    std::copy(pairing_psk_.begin(), pairing_psk_.end(), payload.begin() + 32);

    std::string body = base32_encode(payload.data(), payload.size());

    // Sendspin pairing-token alphabet:
    // transliterate Base32 '2' to '9'
    std::replace(body.begin(), body.end(), '2', '9');

    return std::string("SP:0") + body;
}

bool SendspinSecurityState::find_psk(const std::string& requested_id, const std::string& server_id,
                                     std::array<uint8_t, 32>& psk, SendspinPskKind& kind) {
    if (pairing_psk_enabled_ && requested_id == psk_id(pairing_psk_)) {
        psk = pairing_psk_;
        kind = SendspinPskKind::PAIRING;
        return true;
    }
    for (auto& record : records_) {
        if ((record.server_id.empty() || record.server_id == server_id) &&
            requested_id == psk_id(record.psk)) {
            psk = record.psk;
            kind = SendspinPskKind::LONG_TERM;
            mark_record_used(record);
            return true;
        }
    }
    std::array<uint8_t, 32> sentinel{};
    std::copy(std::begin(SENTINEL_PSK_BYTES), std::end(SENTINEL_PSK_BYTES), sentinel.begin());
    if (requested_id == psk_id(sentinel)) {
        psk = sentinel;
        kind = SendspinPskKind::SENTINEL;
        return true;
    }
    return false;
}

bool SendspinSecurityState::add_record(const std::string& server_id,
                                       const std::array<uint8_t, 32>& psk) {
    if (server_id.empty()) return false;
    for (auto& record : records_) {
        if (record.server_id == server_id) {
            record.psk = psk;
            if (persistence_) {
                return persistence_->save_pairing_record(
                    server_id, base64url_encode(psk.data(), psk.size()));
            }
            return true;
        }
    }
    records_.push_back({server_id, psk});
    if (persistence_) {
        return persistence_->save_pairing_record(server_id,
                                                 base64url_encode(psk.data(), psk.size()));
    }
    return true;
}

bool SendspinSecurityState::has_record_for_server(const std::string& server_id) const {
    return std::any_of(records_.begin(), records_.end(), [&](const auto& record) {
        return record.server_id == server_id;
    });
}


bool SendspinSecurityState::persist_security_value(const std::string& key, const std::string& value) {
    return persistence_ == nullptr || persistence_->save_security_value(key, value);
}

bool SendspinSecurityState::load_bool_security_value(const std::string& key, bool fallback) const {
    if (!persistence_) return fallback;
    const auto value = persistence_->load_security_value(key);
    if (!value.has_value()) return fallback;
    if (*value == "true") return true;
    if (*value == "false") return false;
    return fallback;
}

bool SendspinSecurityState::is_reserved_psk_id(const std::string& id) const {
    std::array<uint8_t, 32> sentinel{};
    std::copy(std::begin(SENTINEL_PSK_BYTES), std::end(SENTINEL_PSK_BYTES), sentinel.begin());
    if (id == psk_id(sentinel) || id == psk_id(pairing_psk_)) return true;
    return std::any_of(records_.begin(), records_.end(), [&](const auto& record) {
        return id == psk_id(record.psk);
    });
}

bool SendspinSecurityState::mark_record_used(SendspinPairingRecord& record) {
    if (record.used) return true;
    record.used = true;
    return persist_security_value("management.used." + psk_id(record.psk), "1");
}

SendspinManagementResult SendspinSecurityState::add_management_record(
    const std::string& server_id, const std::string& encoded_psk) {
    std::vector<uint8_t> raw;
    if (!base64url_decode(encoded_psk, raw) || raw.size() != 32 || encoded_psk.size() != 43)
        return SendspinManagementResult::INVALID;
    std::array<uint8_t, 32> psk{};
    std::copy(raw.begin(), raw.end(), psk.begin());
    const std::string id = psk_id(psk);
    if (is_reserved_psk_id(id)) return SendspinManagementResult::ALREADY_EXISTS;
    SendspinPairingRecord record{server_id, psk, false};
    records_.push_back(record);
    bool ok = true;
    if (persistence_) {
        if (server_id.empty()) {
            const std::string existing_ids =
                persistence_->load_security_value("management.shared_ids").value_or("");
            const std::string next_ids = existing_ids.empty() ? id : existing_ids + "," + id;
            ok = persistence_->save_security_value("management.shared." + id, encoded_psk) &&
                 persistence_->save_security_value("management.shared_ids", next_ids);
        } else {
            ok = persistence_->save_pairing_record(server_id, encoded_psk);
        }
        ok = persistence_->save_security_value("management.used." + id, "0") &&
             persistence_->save_security_value("management.removed." + id, "0") && ok;
    }
    if (!ok) {
        records_.pop_back();
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    }
    return SendspinManagementResult::OK;
}

SendspinManagementResult SendspinSecurityState::remove_management_record(
    const std::string& record_psk_id) {
    auto it = std::find_if(records_.begin(), records_.end(), [&](const auto& record) {
        return psk_id(record.psk) == record_psk_id;
    });
    if (it == records_.end()) return SendspinManagementResult::NOT_FOUND;
    if (record_psk_id == record_mode_psk_id_) return SendspinManagementResult::INVALID;
    if (!persist_security_value("management.removed." + record_psk_id, "1"))
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    records_.erase(it);
    return SendspinManagementResult::OK;
}

SendspinManagementResult SendspinSecurityState::set_pairing_psk_enabled(bool enabled) {
    if (!persist_security_value("management.pairing_psk_enabled", enabled ? "true" : "false"))
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    pairing_psk_enabled_ = enabled;
    return SendspinManagementResult::OK;
}

SendspinManagementResult SendspinSecurityState::replace_pairing_psk(const std::string& encoded_psk) {
    std::vector<uint8_t> raw;
    if (!base64url_decode(encoded_psk, raw) || raw.size() != 32 || encoded_psk.size() != 43)
        return SendspinManagementResult::INVALID;
    std::array<uint8_t, 32> next{};
    std::copy(raw.begin(), raw.end(), next.begin());
    const std::string id = psk_id(next);
    std::array<uint8_t, 32> sentinel{};
    std::copy(std::begin(SENTINEL_PSK_BYTES), std::end(SENTINEL_PSK_BYTES), sentinel.begin());
    if (id == psk_id(sentinel) || std::any_of(records_.begin(), records_.end(), [&](const auto& r) {
            return id == psk_id(r.psk);
        })) return SendspinManagementResult::ALREADY_EXISTS;
    if (persistence_ && !persistence_->save_pairing_psk(encoded_psk))
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    pairing_psk_ = next;
    return SendspinManagementResult::OK;
}

SendspinManagementResult SendspinSecurityState::set_unpaired_access(bool enabled) {
    if (!persist_security_value("management.unpaired_access", enabled ? "true" : "false"))
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    unpaired_access_enabled_ = enabled;
    return SendspinManagementResult::OK;
}

SendspinManagementResult SendspinSecurityState::set_record_mode(const std::string& record_psk_id) {
    const bool valid = std::any_of(records_.begin(), records_.end(), [&](const auto& record) {
        return record.server_id.empty() && psk_id(record.psk) == record_psk_id;
    });
    if (!valid) return SendspinManagementResult::INVALID;
    if (!persist_security_value("management.record_mode_psk_id", record_psk_id))
        return SendspinManagementResult::STORAGE_EXHAUSTED;
    record_mode_psk_id_ = record_psk_id;
    return SendspinManagementResult::OK;
}

NoiseResponderSession::NoiseResponderSession() = default;
NoiseResponderSession::~NoiseResponderSession() = default;

bool NoiseResponderSession::sha256(const uint8_t* data, size_t len,
                                   std::array<uint8_t, 32>& out) {
    return SHA256(data, len, out.data()) != nullptr;
}

bool NoiseResponderSession::hkdf(const std::array<uint8_t, 32>& chaining_key,
                                 const uint8_t* input, size_t input_len, size_t outputs,
                                 std::array<std::array<uint8_t, 32>, 3>& out) {
    if (outputs < 1 || outputs > 3) return false;
    unsigned int prk_len = 0;
    std::array<uint8_t, 32> prk{};
    if (!HMAC(EVP_sha256(), chaining_key.data(), static_cast<int>(chaining_key.size()), input,
              input_len, prk.data(), &prk_len) || prk_len != 32) return false;

    std::array<uint8_t, 33> buf{};
    unsigned int len = 0;
    buf[0] = 1;
    if (!HMAC(EVP_sha256(), prk.data(), static_cast<int>(prk.size()), buf.data(), 1,
              out[0].data(), &len) || len != 32) return false;
    for (size_t i = 1; i < outputs; ++i) {
        std::memcpy(buf.data(), out[i - 1].data(), 32);
        buf[32] = static_cast<uint8_t>(i + 1);
        if (!HMAC(EVP_sha256(), prk.data(), static_cast<int>(prk.size()), buf.data(), 33,
                  out[i].data(), &len) || len != 32) return false;
    }
    return true;
}

bool NoiseResponderSession::aead_encrypt(CipherState& cipher, const uint8_t* ad, size_t ad_len,
                                         const uint8_t* plaintext, size_t plaintext_len,
                                         std::vector<uint8_t>& ciphertext) {
    if (!cipher.has_key) {
        ciphertext.assign(plaintext, plaintext + plaintext_len);
        return true;
    }
    if (cipher.nonce == UINT64_MAX) return false;
    uint8_t nonce[12]{};
    for (size_t i = 0; i < 8; ++i) nonce[4 + i] = static_cast<uint8_t>((cipher.nonce >> (8 * i)) & 0xff);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, cipher.key.data(), nonce) == 1;
    int out_len = 0;
    if (ok && ad_len > 0) ok = EVP_EncryptUpdate(ctx, nullptr, &out_len, ad, static_cast<int>(ad_len)) == 1;
    ciphertext.resize(plaintext_len + 16);
    int total = 0;
    if (ok && plaintext_len > 0) {
        ok = EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext,
                               static_cast<int>(plaintext_len)) == 1;
        total += out_len;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &out_len) == 1;
        total += out_len;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext.data() + total) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    ciphertext.resize(static_cast<size_t>(total) + 16);
    ++cipher.nonce;
    return true;
}

bool NoiseResponderSession::aead_decrypt(CipherState& cipher, const uint8_t* ad, size_t ad_len,
                                         const uint8_t* ciphertext, size_t ciphertext_len,
                                         std::vector<uint8_t>& plaintext) {
    if (!cipher.has_key) {
        plaintext.assign(ciphertext, ciphertext + ciphertext_len);
        return true;
    }
    if (ciphertext_len < 16 || cipher.nonce == UINT64_MAX) return false;
    const size_t body_len = ciphertext_len - 16;
    uint8_t nonce[12]{};
    for (size_t i = 0; i < 8; ++i) nonce[4 + i] = static_cast<uint8_t>((cipher.nonce >> (8 * i)) & 0xff);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, cipher.key.data(), nonce) == 1;
    int out_len = 0;
    if (ok && ad_len > 0) ok = EVP_DecryptUpdate(ctx, nullptr, &out_len, ad, static_cast<int>(ad_len)) == 1;
    plaintext.resize(body_len);
    int total = 0;
    if (ok && body_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext,
                               static_cast<int>(body_len)) == 1;
        total += out_len;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                      const_cast<uint8_t*>(ciphertext + body_len)) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &out_len) == 1;
    if (ok) total += out_len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    plaintext.resize(static_cast<size_t>(total));
    ++cipher.nonce;
    return true;
}

bool NoiseResponderSession::mix_hash(const uint8_t* data, size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, h_.data(), h_.size());
    if (len) SHA256_Update(&ctx, data, len);
    SHA256_Final(h_.data(), &ctx);
    return true;
}

bool NoiseResponderSession::mix_key(const uint8_t* data, size_t len) {
    std::array<std::array<uint8_t, 32>, 3> out{};
    if (!hkdf(ck_, data, len, 2, out)) return false;
    ck_ = out[0];
    handshake_cipher_.key = out[1];
    handshake_cipher_.nonce = 0;
    handshake_cipher_.has_key = true;
    return true;
}

bool NoiseResponderSession::mix_key_and_hash(const uint8_t* data, size_t len) {
    std::array<std::array<uint8_t, 32>, 3> out{};
    if (!hkdf(ck_, data, len, 3, out)) return false;
    ck_ = out[0];
    if (!mix_hash(out[1].data(), out[1].size())) return false;
    handshake_cipher_.key = out[2];
    handshake_cipher_.nonce = 0;
    handshake_cipher_.has_key = true;
    return true;
}

bool NoiseResponderSession::decrypt_and_hash(const uint8_t* data, size_t len,
                                             std::vector<uint8_t>& plaintext) {
    if (!aead_decrypt(handshake_cipher_, h_.data(), h_.size(), data, len, plaintext)) return false;
    return mix_hash(data, len);
}

bool NoiseResponderSession::encrypt_and_hash(const uint8_t* data, size_t len,
                                             std::vector<uint8_t>& ciphertext) {
    if (!aead_encrypt(handshake_cipher_, h_.data(), h_.size(), data, len, ciphertext)) return false;
    return mix_hash(ciphertext.data(), ciphertext.size());
}

bool NoiseResponderSession::dh(const std::array<uint8_t, 32>& priv,
                               const std::array<uint8_t, 32>& pub,
                               std::array<uint8_t, 32>& out) const {
    EVP_PKEY* private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
    EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pub.data(), 32);
    if (!private_key || !public_key) {
        EVP_PKEY_free(private_key); EVP_PKEY_free(public_key); return false;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    size_t out_len = out.size();
    const bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, public_key) == 1 &&
                    EVP_PKEY_derive(ctx, out.data(), &out_len) == 1 && out_len == out.size();
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(private_key); EVP_PKEY_free(public_key);
    if (!ok) return false;
    return std::any_of(out.begin(), out.end(), [](uint8_t b) { return b != 0; });
}

bool NoiseResponderSession::begin(const std::array<uint8_t, 32>& local_private,
                                  const std::array<uint8_t, 32>& local_public,
                                  const std::array<uint8_t, 32>& remote_public,
                                  const uint8_t* prologue, size_t prologue_len) {
    local_private_ = local_private;
    local_public_ = local_public;
    remote_public_ = remote_public;
    message1_read_ = false;
    transport_ready_ = false;
    handshake_cipher_ = {};
    receive_cipher_ = {};
    send_cipher_ = {};

    const size_t name_len = sizeof(NOISE_NAME) - 1;
    if (name_len <= 32) {
        h_.fill(0);
        std::memcpy(h_.data(), NOISE_NAME, name_len);
    } else if (!sha256(reinterpret_cast<const uint8_t*>(NOISE_NAME), name_len, h_)) {
        return false;
    }
    ck_ = h_;
    if (prologue_len > 0 && !mix_hash(prologue, prologue_len)) return false;
    // KK pre-messages: initiator static first (server), responder static second (client).
    if (!mix_hash(remote_public_.data(), remote_public_.size())) return false;
    if (!mix_hash(local_public_.data(), local_public_.size())) return false;
    return true;
}

bool NoiseResponderSession::read_message1(const uint8_t* message, size_t len,
                                          std::string& payload_json) {
    if (len < 32 + 16 || message1_read_) return false;
    std::copy(message, message + 32, remote_ephemeral_.begin());
    if (!mix_hash(remote_ephemeral_.data(), remote_ephemeral_.size())) return false;
    // Any Noise pattern containing a PSK mixes the ephemeral public key into ck at e tokens.
    if (!mix_key(remote_ephemeral_.data(), remote_ephemeral_.size())) return false;
    std::array<uint8_t, 32> shared{};
    // es: responder static with initiator ephemeral.
    if (!dh(local_private_, remote_ephemeral_, shared) || !mix_key(shared.data(), shared.size())) return false;
    // ss: responder static with initiator static.
    if (!dh(local_private_, remote_public_, shared) || !mix_key(shared.data(), shared.size())) return false;
    std::vector<uint8_t> payload;
    if (!decrypt_and_hash(message + 32, len - 32, payload)) return false;
    payload_json.assign(payload.begin(), payload.end());
    message1_read_ = true;
    return true;
}

bool NoiseResponderSession::split() {
    std::array<std::array<uint8_t, 32>, 3> out{};
    if (!hkdf(ck_, nullptr, 0, 2, out)) return false;
    // Split returns initiator->responder first, responder->initiator second.
    receive_cipher_.key = out[0];
    receive_cipher_.nonce = 0;
    receive_cipher_.has_key = true;
    send_cipher_.key = out[1];
    send_cipher_.nonce = 0;
    send_cipher_.has_key = true;
    transport_ready_ = true;
    return true;
}

bool NoiseResponderSession::write_message2(const std::array<uint8_t, 32>& psk,
                                           const std::string& payload_json,
                                           std::vector<uint8_t>& out) {
    if (!message1_read_) return false;
    if (!SendspinSecurityState::random_bytes(local_ephemeral_private_.data(), local_ephemeral_private_.size()) ||
        !derive_public(local_ephemeral_private_, local_ephemeral_public_)) return false;
    out.clear();
    out.insert(out.end(), local_ephemeral_public_.begin(), local_ephemeral_public_.end());
    if (!mix_hash(local_ephemeral_public_.data(), local_ephemeral_public_.size())) return false;
    if (!mix_key(local_ephemeral_public_.data(), local_ephemeral_public_.size())) return false;
    std::array<uint8_t, 32> shared{};
    // ee
    if (!dh(local_ephemeral_private_, remote_ephemeral_, shared) || !mix_key(shared.data(), shared.size())) return false;
    // se: responder ephemeral with initiator static.
    if (!dh(local_ephemeral_private_, remote_public_, shared) || !mix_key(shared.data(), shared.size())) return false;
    // psk2 at the end of message 2.
    if (!mix_key_and_hash(psk.data(), psk.size())) return false;
    std::vector<uint8_t> encrypted_payload;
    if (!encrypt_and_hash(reinterpret_cast<const uint8_t*>(payload_json.data()), payload_json.size(),
                          encrypted_payload)) return false;
    out.insert(out.end(), encrypted_payload.begin(), encrypted_payload.end());
    return split();
}

bool NoiseResponderSession::encrypt(const uint8_t* plaintext, size_t len,
                                    std::vector<uint8_t>& ciphertext) {
    if (!transport_ready_) return false;
    return aead_encrypt(send_cipher_, nullptr, 0, plaintext, len, ciphertext);
}

bool NoiseResponderSession::decrypt(const uint8_t* ciphertext, size_t len,
                                    std::vector<uint8_t>& plaintext) {
    if (!transport_ready_) return false;
    return aead_decrypt(receive_cipher_, nullptr, 0, ciphertext, len, plaintext);
}

}  // namespace sendspin

#endif
