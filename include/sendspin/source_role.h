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

/// @file source_role.h
/// @brief Audio capture role that streams audio from the client to the Sendspin server

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Source types
// ============================================================================

/// @brief Line-input signal state reported by the source role in client/state messages
enum class SourceSignal : uint8_t {
    PRESENT,  // Audio signal detected on the capture input
    ABSENT,   // No audio signal on the capture input
};

/// @brief Playback position of the input audio (roles/source/v1.md "client/state source object")
struct SourceMetadataProgress {
    uint32_t track_progress_ms{0};
    uint32_t track_duration_ms{0};  ///< 0 for unknown or unlimited
    uint32_t playback_speed{1000};  ///< Speed multiplier * 1000; 0 is paused
};

/// @brief What the input audio is, for SourceRole::set_metadata(). The text is copied before the
/// call returns; each field longer than the spec's cap (255 bytes, 2048 for artwork_url) is cut
/// at a UTF-8 boundary.
struct SourceMetadata {
    /// @brief Local-clock time (SendspinClient::now_us()) at which `progress` was measured, or 0
    /// for the time of the call. Converted to the server clock when each client/state is sent.
    int64_t timestamp_us{0};
    std::optional<std::string_view> title{};
    std::optional<std::string_view> artist{};
    std::optional<std::string_view> album_artist{};
    std::optional<std::string_view> album{};
    std::optional<std::string_view> artwork_url{};
    std::optional<uint16_t> year{};
    std::optional<uint16_t> track{};  ///< At least 1
    std::optional<SourceMetadataProgress> progress{};
};

/// @brief Listener for source role events. All methods fire on the main loop thread.
class SourceRoleListener {
public:
    virtual ~SourceRoleListener() = default;

    /// @brief Called when the input stream to the server has opened (client-stream/start was
    /// sent); write_audio() accepts audio from this point on
    virtual void on_streaming_started() {}

    /// @brief Called when the input stream has closed (a server stop, the role being removed, the
    /// server dropping the 'playback' activity, the client becoming unavailable, the connection
    /// ending, or the client stopping); write_audio() rejects audio again
    virtual void on_streaming_stopped() {}
};

/**
 * @brief Audio capture role that streams audio to the server
 *
 * The server decides when the role streams (roles/source/v1.md "Source command semantics"):
 * nothing is sent until a server start, and each start authorizes one opening of the input
 * stream. Once open, the role announces its capture format in client-stream/start and forwards
 * the audio written to write_audio() as timestamped chunks until client-stream/end.
 *
 * Usage:
 * 1. Implement SourceRoleListener to learn when the stream opens and closes
 * 2. Add the role to the client via SendspinClient::add_source() with the capture format
 * 3. Call set_listener() with your listener implementation
 * 4. Feed captured audio to write_audio() from your capture thread
 *
 * @code
 * struct MySourceListener : SourceRoleListener {
 *     void on_streaming_started() override { capture.enable(); }
 *     void on_streaming_stopped() override { capture.disable(); }
 * };
 *
 * MySourceListener listener;
 * auto& source = client.add_source(SourceRoleConfig{});
 * source.set_listener(&listener);
 *
 * // Capture thread:
 * source.write_audio(pcm_frames, len, capture_time_us);
 * @endcode
 */
class SourceRole {
    friend class SendspinClient;

public:
    struct Impl;

    SourceRole(SourceRoleConfig config, SendspinClient* client);
    ~SourceRole();

    /// @brief Sets the listener for source events; it must outlive this role. Main loop only:
    /// set it before SendspinClient::start() and leave it in place while the client runs.
    void set_listener(SourceRoleListener* listener);

    /// @brief Writes captured audio into the input stream
    ///
    /// Never allocates and never waits: the audio is copied into the capture buffer, which the
    /// library's source task drains into chunks, under only the capture ring's own short leaf
    /// lock. Exactly one producer thread may call this, and it must have stopped calling before
    /// the client is destroyed.
    ///
    /// @param data Interleaved little-endian signed PCM in the configured format (24-bit as 3
    ///        packed bytes per sample); never null.
    /// @param len Length in bytes; a write that is not a whole number of frames (one sample
    ///        across all channels) is rejected as a whole.
    /// @param capture_time_us Local-clock capture time (platform time, the domain of
    ///        SendspinClient::get_client_time()) of the FIRST sample in data, or 0 to stamp the
    ///        write as ending at the current time (its first sample one write duration earlier).
    /// @return true if the audio was accepted; false when the stream is not open, the write is
    ///         not whole frames or longer than the capture buffer ever takes in one write
    ///         (SourceRoleConfig::capture_buffer_ms), or the capture buffer is full (the write is
    ///         dropped, and the stream resumes from live capture once the buffer drains).
    bool write_audio(const uint8_t* data, size_t len, int64_t capture_time_us);

    /// @brief Reports the capture input's signal state, published to the server in client/state
    ///
    /// Main loop only. Every client/state carries one (roles/source/v1.md "client/state source
    /// object"); it is ABSENT until this is first called, so a source that never detects
    /// anything never hints a start.
    void set_signal(SourceSignal signal);

    /// @brief Reports what the input audio is, published to the server in client/state
    ///
    /// Main loop only. Needs SourceRoleConfig::metadata. Send it when the metadata or the playback
    /// state changes, not to advance the position: the server extrapolates that from `progress`
    /// (roles/source/v1.md "Source metadata").
    /// @return false, changing nothing, without SourceRoleConfig::metadata, when its block could
    ///         not be reserved, or when a text field is not valid UTF-8 or `track` is 0.
    bool set_metadata(const SourceMetadata& metadata);

    /// @brief Withdraws the metadata set_metadata() reported. Main loop only.
    void clear_metadata();

    /// @brief Whether the input stream is open, as the started/stopped callbacks last reported.
    /// Main loop only.
    bool is_streaming() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
