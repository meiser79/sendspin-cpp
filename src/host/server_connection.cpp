// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "server_connection.h"

#include "platform/logging.h"
#include "platform/time.h"
#include "protocol_messages.h"

#include <ArduinoJson.h>

#include <algorithm>
#include <cstring>

namespace sendspin {

static const char* const TAG = "sendspin.server_connection";

SendspinServerConnection::SendspinServerConnection(std::shared_ptr<ix::WebSocket> ws, int sockfd)
    : ws_(std::move(ws)), sockfd_(sockfd) {
    // No TCP_NODELAY setsockopt is needed here: IXWebSocket disables Nagle on accepted sockets
    // itself. SocketServer::run() calls SocketConnect::configure(clientFd) on every accepted
    // client fd (the same routine that sets TCP_NODELAY on outbound connects) so time messages
    // on this host-server path are not subject to Nagle coalescing delay.
}

void SendspinServerConnection::start() {
    // No action needed: the connection is constructed by the ws_server only after the WebSocket
    // Open event, so the transport is already established and upgraded by the time it exists.
}

void SendspinServerConnection::loop() {
    // Time message sending is handled by the hub
}

void SendspinServerConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye message, then close
    this->send_goodbye_reason(reason, [this, on_complete](bool /*success*/) {
        this->trigger_close();
        if (on_complete) {
            on_complete();
        }
    });
}

bool SendspinServerConnection::is_connected() const {
    return this->ws_ && this->ws_->getReadyState() == ix::ReadyState::Open;
}

void SendspinServerConnection::configure_security(SendspinSecurityState* state,
                                                  bool unpaired_access) {
    this->security_state_ = state;
    this->unpaired_access_ = unpaired_access;
    this->security_phase_ = state ? SecurityPhase::IDLE : SecurityPhase::DISABLED;
}

bool SendspinServerConnection::send_raw_text(const std::string& text) {
    return this->is_connected() && this->ws_->send(text).success;
}

bool SendspinServerConnection::send_raw_binary(const uint8_t* data, size_t len) {
    if (!this->is_connected() || !data || len == 0) return false;
    return this->ws_->sendBinary(std::string(reinterpret_cast<const char*>(data), len)).success;
}

bool SendspinServerConnection::begin_security_handshake() {
    if (!this->security_state_ || this->security_phase_ != SecurityPhase::IDLE || !this->is_connected()) {
        return false;
    }
    this->client_init_raw_ =
        std::string("{\"type\":\"client/init\",\"payload\":{\"client_id\":\"") +
        this->security_state_->client_id() +
        "\",\"version\":1,\"suite\":\"25519_ChaChaPoly_SHA256\"}}";
    if (!this->send_raw_text(this->client_init_raw_)) return false;
    this->security_phase_ = SecurityPhase::WAIT_SERVER_INIT;
    SS_LOGD(TAG, "Sent client/init for %s", this->security_state_->client_id().c_str());
    return true;
}

const char* SendspinServerConnection::trust_level() const {
    return this->matched_psk_kind_ == SendspinPskKind::LONG_TERM ? "user" : "none";
}

bool SendspinServerConnection::set_pending_pairing_psk(const std::array<uint8_t, 32>& psk) {
    this->pending_pairing_psk_ = psk;
    return true;
}

bool SendspinServerConnection::commit_pending_pairing_psk() {
    if (!this->pending_pairing_psk_ || !this->security_state_ || this->security_server_id_.empty()) {
        return false;
    }
    const bool ok = this->security_state_->add_record(this->security_server_id_,
                                                       *this->pending_pairing_psk_);
    if (ok) this->pending_pairing_psk_.reset();
    return ok;
}

SsErr SendspinServerConnection::send_binary_message(const uint8_t* data, size_t len) {
    if (!this->is_connected() || data == nullptr || len == 0) return SsErr::INVALID_STATE;
    if (!this->security_state_) {
        return this->send_raw_binary(data, len) ? SsErr::OK : SsErr::FAIL;
    }
    // During an initial hello exchange or an in-band Noise re-handshake, application
    // traffic must stay quiescent.  In particular, a role/state frame must never overtake
    // Noise message 2, which is still carried under the old transport keys.
    if (!this->is_handshake_complete()) return SsErr::INVALID_STATE;
    if (this->security_phase_ != SecurityPhase::TRANSPORT || !this->noise_session_) {
        return SsErr::INVALID_STATE;
    }
    std::vector<uint8_t> ciphertext;
    if (!this->noise_session_->encrypt(data, len, ciphertext)) return SsErr::FAIL;
    return this->send_raw_binary(ciphertext.data(), ciphertext.size()) ? SsErr::OK : SsErr::FAIL;
}

SsErr SendspinServerConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback on_complete,
                                                  bool allow_before_hello) {
    if (!this->is_connected()) {
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::INVALID_STATE;
    }
    bool success = false;
    if (!this->security_state_) {
        success = this->send_raw_text(message);
    } else if (!allow_before_hello && !this->is_handshake_complete()) {
        // Secure application traffic is forbidden while the hello exchange is incomplete.
        // The explicit bypass is reserved for protocol-control messages such as client/hello,
        // goodbye, and Noise message 2 during an in-band re-handshake.
        success = false;
    } else if (this->security_phase_ == SecurityPhase::TRANSPORT && this->noise_session_) {
        std::vector<uint8_t> plaintext;
        plaintext.reserve(message.size() + 1);
        plaintext.push_back(0);
        plaintext.insert(plaintext.end(), message.begin(), message.end());
        std::vector<uint8_t> ciphertext;
        success = this->noise_session_->encrypt(plaintext.data(), plaintext.size(), ciphertext) &&
                  this->send_raw_binary(ciphertext.data(), ciphertext.size());
    }
    if (on_complete) {
        on_complete(success);
    }
    return success ? SsErr::OK : SsErr::FAIL;
}

bool SendspinServerConnection::send_time_message() {
    if (!this->is_connected()) {
        return false;
    }

    char buf[TIME_MESSAGE_BUF_SIZE];
    const int64_t client_transmitted = platform_time_us();
    const size_t len = format_client_time_message(buf, sizeof(buf), client_transmitted);
    if (len == 0) {
        return false;
    }
    this->update_serialize_ema(platform_time_us() - client_transmitted);
    return this->send_text_message(std::string(buf, len), nullptr, false) == SsErr::OK;
}

void SendspinServerConnection::trigger_close() {
    if (this->ws_) {
        this->ws_->close();
    }
}

bool SendspinServerConnection::handle_secure_text(const std::string& data, int64_t receive_time) {
    (void)receive_time;
    JsonDocument doc;
    if (deserializeJson(doc, data) != DeserializationError::Ok) return false;
    const char* type = doc["type"] | "";
    if (this->security_phase_ == SecurityPhase::WAIT_SERVER_INIT) {
        if (std::strcmp(type, "server/init") != 0) return false;
        const char* server_id = doc["payload"]["server_id"] | "";
        const int version = doc["payload"]["version"] | 0;
        if (version != 1 || std::strlen(server_id) != 43) return false;
        std::vector<uint8_t> raw_key;
        if (!SendspinSecurityState::base64url_decode(server_id, raw_key) || raw_key.size() != 32) {
            return false;
        }
        this->security_server_id_ = server_id;
        std::copy(raw_key.begin(), raw_key.end(), this->security_server_public_.begin());
        this->server_init_raw_ = data;
        this->security_phase_ = SecurityPhase::WAIT_NOISE1;
        return true;
    }
    if (this->security_phase_ == SecurityPhase::WAIT_NOISE1) {
        if (std::strcmp(type, "noise/handshake") != 0) return false;
        return this->handle_noise_message1(data, false);
    }
    return false;
}

bool SendspinServerConnection::handle_noise_message1(const std::string& json, bool rehandshake) {
    JsonDocument doc;
    if (deserializeJson(doc, json) != DeserializationError::Ok) return false;
    if (std::strcmp(doc["type"] | "", "noise/handshake") != 0) return false;
    const char* encoded = doc["payload"]["data"] | "";
    std::vector<uint8_t> message1;
    if (!SendspinSecurityState::base64url_decode(encoded, message1)) return false;

    auto next = std::make_unique<NoiseResponderSession>();
    std::vector<uint8_t> prologue;
    if (rehandshake) {
        if (!this->noise_session_) return false;
        const auto& h = this->noise_session_->handshake_hash();
        prologue.assign(h.begin(), h.end());
    } else {
        prologue.insert(prologue.end(), this->client_init_raw_.begin(), this->client_init_raw_.end());
        prologue.insert(prologue.end(), this->server_init_raw_.begin(), this->server_init_raw_.end());
    }
    if (!next->begin(this->security_state_->private_key(), this->security_state_->public_key(),
                     this->security_server_public_, prologue.data(), prologue.size())) return false;

    std::string inner;
    if (!next->read_message1(message1.data(), message1.size(), inner)) return false;
    JsonDocument inner_doc;
    if (deserializeJson(inner_doc, inner) != DeserializationError::Ok) return false;
    const char* requested_id = inner_doc["psk_id"] | "";
    std::array<uint8_t, 32> psk{};
    SendspinPskKind kind{};
    if (!this->security_state_->find_psk(requested_id, this->security_server_id_, psk, kind)) {
        SS_LOGW(TAG, "Noise PSK id is unknown");
        return false;
    }

    std::vector<uint8_t> message2;
    if (!next->write_message2(psk, "{}", message2)) return false;
    const std::string response =
        std::string("{\"type\":\"noise/handshake\",\"payload\":{\"data\":\"") +
        SendspinSecurityState::base64url_encode(message2.data(), message2.size()) + "\"}}";

    bool sent = false;
    if (rehandshake) {
        // Message 2 of an in-band re-handshake is encrypted with the OLD transport keys.
        sent = this->send_text_message(response, nullptr, true) == SsErr::OK;
    } else {
        sent = this->send_raw_text(response);
    }
    if (!sent) return false;

    this->noise_session_ = std::move(next);
    this->matched_psk_kind_ = kind;
    this->matched_psk_id_ = requested_id;
    this->security_phase_ = SecurityPhase::TRANSPORT;
    // A re-handshake starts a fresh hello/activate exchange.
    this->client_hello_sent_ = false;
    this->server_hello_received_ = false;
    SS_LOGI(TAG, "Noise transport established (trust=%s, psk=%s)", this->trust_level(),
            kind == SendspinPskKind::PAIRING ? "pairing" :
            kind == SendspinPskKind::LONG_TERM ? "long-term" : "sentinel");
    return true;
}

bool SendspinServerConnection::dispatch_decrypted(const std::vector<uint8_t>& plaintext,
                                                  int64_t receive_time) {
    if (plaintext.empty()) return false;
    if (plaintext[0] == 0) {
        const std::string json(reinterpret_cast<const char*>(plaintext.data() + 1),
                               plaintext.size() - 1);
        JsonDocument doc;
        if (deserializeJson(doc, json) == DeserializationError::Ok &&
            std::strcmp(doc["type"] | "", "noise/handshake") == 0) {
            // Quiesce ordinary client traffic before generating Noise message 2.  These are
            // atomics because state/time/role publishers can run on threads other than this
            // WebSocket callback thread.  Noise message 2 itself uses allow_before_hello=true.
            this->client_hello_sent_.store(false, std::memory_order_release);
            this->server_hello_received_.store(false, std::memory_order_release);
            return this->handle_noise_message1(json, true);
        }
        if (this->on_json_message_cb) {
            this->on_json_message_cb(this, json.data(), json.size(), receive_time);
        }
        return true;
    }
    if (this->on_binary_message_cb) {
        // Existing core binary dispatch expects the type byte to be present.
        this->on_binary_message_cb(this, const_cast<uint8_t*>(plaintext.data()), plaintext.size());
    }
    return true;
}

bool SendspinServerConnection::handle_secure_binary(const std::string& data, int64_t receive_time) {
    if (this->security_phase_ != SecurityPhase::TRANSPORT || !this->noise_session_) return false;
    std::vector<uint8_t> plaintext;
    if (!this->noise_session_->decrypt(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                       plaintext)) {
        SS_LOGW(TAG, "Noise transport decrypt failed");
        return false;
    }
    return this->dispatch_decrypted(plaintext, receive_time);
}

void SendspinServerConnection::handle_message(const std::string& data, bool is_binary,
                                              int64_t receive_time) {
    if (this->security_state_) {
        const bool ok = is_binary ? this->handle_secure_binary(data, receive_time)
                                  : this->handle_secure_text(data, receive_time);
        if (!ok) {
            SS_LOGW(TAG, "Invalid secure-protocol message; closing connection");
            this->trigger_close();
        }
        return;
    }

    if (!data.empty()) {
        uint8_t* dest = this->prepare_receive_buffer(data.size());
        if (dest == nullptr) {
            // Dispatching would hand a stale/partial buffer to the protocol layer. Drop the
            // connection instead: the close event tears the slot down on the main loop.
            SS_LOGE(TAG, "Allocation failed, dropping connection");
            this->disable_message_dispatch();
            this->reset_websocket_payload();
            this->trigger_close();
            return;
        }
        std::copy(data.begin(), data.end(), dest);
        this->commit_receive_buffer(data.size());
    }
    this->dispatch_completed_message(!is_binary, receive_time);
}

}  // namespace sendspin
