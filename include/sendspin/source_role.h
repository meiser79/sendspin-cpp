#pragma once

#include "sendspin/config.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;
struct ClientStateMessage;

/// Source input format announced in client-stream/start.
struct SourceAudioFormat {
    SendspinCodecFormat codec{SendspinCodecFormat::PCM};
    uint32_t sample_rate{48000};
    uint8_t channels{2};
    uint8_t bit_depth{16};
    std::optional<std::string> codec_header{};
};

/// source@v1 capability configuration.
struct SourceRoleConfig {
    SourceAudioFormat format{};
    bool line_sense{true};
};

enum class SendspinSourceSignal : uint8_t { ABSENT, PRESENT };

/// Receives source lifecycle notifications on the Sendspin main-loop thread.
class SourceRoleListener {
public:
    virtual ~SourceRoleListener() = default;
    virtual void on_source_start() {}
    virtual void on_source_stop() {}
};

class SourceRole {
public:
    SourceRole(SourceRoleConfig config, SendspinClient* client);
    ~SourceRole();
    SourceRole(const SourceRole&) = delete;
    SourceRole& operator=(const SourceRole&) = delete;

    void set_listener(SourceRoleListener* listener);

    /// True only after server/command source.start and before source.stop/disconnect.
    bool streaming() const;

    /// Send one encoded source chunk. capture_time_us is in the local monotonic clock domain
    /// and is converted to the synchronized server clock by SendspinClient.
    /// For PCM, data must contain whole interleaved PCM frames.
    bool send_audio(const uint8_t* data, size_t len, int64_t capture_time_us);

    /// Publish line-sense state if line_sense was enabled in SourceRoleConfig.
    void update_signal(SendspinSourceSignal signal);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    friend class SendspinClient;
};

} // namespace sendspin
