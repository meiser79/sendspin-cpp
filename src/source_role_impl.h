#pragma once

#include "sendspin/source_role.h"
#include <atomic>
#include <mutex>
#include <string>

namespace sendspin {

class SourceRole::Impl {
public:
    Impl(SourceRoleConfig config, SendspinClient* client);

    void build_hello_fields(ClientHelloMessage& msg) const;
    void build_state_fields(ClientStateMessage& msg) const;
    void handle_server_command(const std::string& command);
    void handle_activation(bool active);
    void cleanup();

    bool streaming() const { return streaming_.load(std::memory_order_acquire); }
    bool send_audio(const uint8_t* data, size_t len, int64_t capture_time_us);
    void update_signal(SendspinSourceSignal signal);
    void set_listener(SourceRoleListener* listener) { listener_ = listener; }

private:
    void start_stream();
    void stop_stream();
    std::string format_stream_start() const;

    SourceRoleConfig config_;
    SendspinClient* client_{nullptr};
    SourceRoleListener* listener_{nullptr};
    std::atomic<bool> streaming_{false};
    std::optional<SendspinSourceSignal> signal_{};
    mutable std::mutex state_mutex_;
};

} // namespace sendspin
