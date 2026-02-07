#pragma once

#include <cstdint>
#include <vector>

#include "core/serialize.h"
#include "primitives/outpoint.h"

namespace primitives {

/// A transaction input, referencing a previous output and providing the
/// unlocking script (and optionally witness data) to spend it.
struct TxInput {
    // ---- Sequence-number flag constants ----

    /// Indicates the input is final (no relative lock-time, no RBF).
    static constexpr uint32_t SEQUENCE_FINAL = 0xFFFFFFFF;

    /// If set, the sequence number is not interpreted as a relative
    /// lock-time.
    static constexpr uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1u << 31);

    /// If set (and disable flag is clear), the lock-time is measured in
    /// 512-second intervals rather than blocks.
    static constexpr uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1u << 22);

    /// Mask for the 16-bit relative lock-time value.
    static constexpr uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000FFFF;

    // ---- Data members ----

    /// The output being spent.
    OutPoint prevout;

    /// The unlocking script (scriptSig).
    std::vector<uint8_t> script_sig;

    /// Sequence number. Controls relative lock-time and opt-in
    /// replace-by-fee behaviour.
    uint32_t sequence = SEQUENCE_FINAL;

    /// Segregated witness stack for this input.
    std::vector<std::vector<uint8_t>> witness;

    TxInput() = default;
    TxInput(OutPoint prevout_in, std::vector<uint8_t> script_sig_in,
            uint32_t sequence_in = SEQUENCE_FINAL);

    /// Returns true if segregated witness data is present.
    [[nodiscard]] bool has_witness() const { return !witness.empty(); }

    /// Serialize the base input (without witness). Witness data is
    /// serialized separately at the transaction level.
    ///
    /// Wire format:
    ///   prevout (36 bytes) | compact_size(script_sig) | script_sig |
    ///   sequence (4 bytes)
    template<typename Stream>
    void serialize(Stream& s) const {
        prevout.serialize(s);
        core::ser_write_compact_size(s, script_sig.size());
        if (!script_sig.empty()) {
            core::ser_write_bytes(
                s,
                std::span<const uint8_t>(
                    script_sig.data(), script_sig.size()));
        }
        core::ser_write_u32(s, sequence);
    }

    /// Deserialize the base input (without witness).
    template<typename Stream>
    static TxInput deserialize(Stream& s) {
        TxInput input;
        input.prevout = OutPoint::deserialize(s);

        uint64_t script_len = core::ser_read_compact_size(s);
        input.script_sig.resize(static_cast<size_t>(script_len));
        if (script_len > 0) {
            core::ser_read_bytes(
                s,
                std::span<uint8_t>(
                    input.script_sig.data(), input.script_sig.size()));
        }

        input.sequence = core::ser_read_u32(s);
        return input;
    }
};

} // namespace primitives
