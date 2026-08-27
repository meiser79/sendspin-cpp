#include "source_role_impl.h"

#include "protocol_messages.h"
#include "sendspin/client.h"
#include "platform/logging.h"
#include <ArduinoJson.h>
#include <algorithm>
#include <cstring>
#include <vector>

namespace sendspin {
namespace {
constexpr uint8_t SOURCE_AUDIO_TYPE = 12;
const char* TAG = "sendspin.source";

const char* signal_to_cstr(SendspinSourceSignal s) {
    return s == SendspinSourceSignal::PRESENT ? "present" : "absent";
}

void put_be64(uint8_t* dst, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        dst[7 - i] = static_cast<uint8_t>((value >> (i * 8)) & 0xffU);
    }
}
}

SourceRole::SourceRole(SourceRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(std::move(config), client)) {}
SourceRole::~SourceRole() = default;
void SourceRole::set_listener(SourceRoleListener* listener) { impl_->set_listener(listener); }
bool SourceRole::streaming() const { return impl_->streaming(); }
bool SourceRole::send_audio(const uint8_t* data, size_t len, int64_t capture_time_us) {
    return impl_->send_audio(data, len, capture_time_us);
}
void SourceRole::update_signal(SendspinSourceSignal signal) { impl_->update_signal(signal); }

SourceRole::Impl::Impl(SourceRoleConfig config, SendspinClient* client)
    : config_(std::move(config)), client_(client) {}

void SourceRole::Impl::build_hello_fields(ClientHelloMessage& msg) const {
    msg.supported_roles.push_back(SendspinRole::SOURCE);
    SourceSupportObject support{};
    support.line_sense = config_.line_sense;
    msg.source_v1_support = support;
}

void SourceRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (!config_.line_sense || client_ == nullptr || !client_->is_role_active("source@v1")) return;
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (!signal_.has_value()) return;
    ClientSourceStateObject source{};
    source.signal = signal_to_cstr(*signal_);
    msg.source = source;
}

std::string SourceRole::Impl::format_stream_start() const {
    JsonDocument doc;
    JsonObject root = doc.to<JsonObject>();
    root["type"] = "client_stream/start";
    JsonObject source = root["payload"]["source"].to<JsonObject>();
    source["codec"] = to_cstr(config_.format.codec);
    source["channels"] = config_.format.channels;
    source["sample_rate"] = config_.format.sample_rate;
    source["bit_depth"] = config_.format.bit_depth;
    if (config_.format.codec_header.has_value()) {
        source["codec_header"] = *config_.format.codec_header;
    }
    std::string out;
    serializeJson(doc, out);
    return out;
}

void SourceRole::Impl::start_stream() {
    bool expected = false;
    if (!streaming_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;
    client_->send_text(format_stream_start());
    SS_LOGI(TAG, "source@v1 streaming started");
    if (listener_) listener_->on_source_start();
}

void SourceRole::Impl::stop_stream() {
    bool expected = true;
    if (!streaming_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) return;
    client_->send_text("{\"type\":\"client_stream/end\",\"payload\":{\"source\":{}}}");
    SS_LOGI(TAG, "source@v1 streaming stopped");
    if (listener_) listener_->on_source_stop();
}

void SourceRole::Impl::handle_activation(bool active) {
    if (!active) stop_stream();
}

void SourceRole::Impl::handle_server_command(const std::string& command) {
    if (client_ == nullptr || !client_->is_role_active("source@v1")) {
        SS_LOGW(TAG, "Ignoring source command while source@v1 is inactive");
        return;
    }
    if (command == "start") start_stream();
    else if (command == "stop") stop_stream();
    else SS_LOGW(TAG, "Unknown source command: %s", command.c_str());
}

void SourceRole::Impl::cleanup() {
    // Streaming state is per-connection. Do not emit client_stream/end here because transport
    // teardown may already be in progress; just reset state and notify capture side.
    if (streaming_.exchange(false, std::memory_order_acq_rel) && listener_) listener_->on_source_stop();
}

bool SourceRole::Impl::send_audio(const uint8_t* data, size_t len, int64_t capture_time_us) {
    if (!streaming() || data == nullptr || len == 0 || client_ == nullptr ||
        !client_->is_role_active("source@v1")) return false;
    if (!client_->is_time_synced()) return false;

    const int64_t server_time = client_->get_server_time(capture_time_us);
    if (server_time == 0) return false;

    std::vector<uint8_t> frame(9 + len);
    frame[0] = SOURCE_AUDIO_TYPE;
    put_be64(frame.data() + 1, static_cast<uint64_t>(server_time));
    std::memcpy(frame.data() + 9, data, len);
    return client_->send_binary(frame.data(), frame.size());
}

void SourceRole::Impl::update_signal(SendspinSourceSignal signal) {
    if (!config_.line_sense || client_ == nullptr) return;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (signal_.has_value() && *signal_ == signal) return;
        signal_ = signal;
    }

    // Keep the latest signal state even before source@v1 is activated.
    // It will then be included in the initial client/state after server/activate.
    if (client_->is_role_active("source@v1")) {
        client_->publish_state();
    }
}

} // namespace sendspin
