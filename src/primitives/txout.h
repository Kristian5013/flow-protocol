#pragma once

#include <cstdint>
#include <vector>

#include "core/serialize.h"
#include "primitives/amount.h"

namespace primitives {

/// A transaction output, pairing an amount with a locking script
/// (scriptPubKey) that defines the spending conditions.
struct TxOutput {
    /// Value of this output in base units.
    Amount amount;

    /// The locking script (scriptPubKey) that must be satisfied to spend
    /// this output.
    std::vector<uint8_t> script_pubkey;

    TxOutput() = default;
    TxOutput(Amount amount_in, std::vector<uint8_t> script_in);

    /// A null output uses the sentinel value -1 for its amount.  This is
    /// used internally to represent "missing" or "unset" outputs.
    [[nodiscard]] bool is_null() const {
        return amount.value() == -1;
    }

    /// Serialize: amount (8 bytes) | compact_size(script) | script bytes.
    template<typename Stream>
    void serialize(Stream& s) const {
        amount.serialize(s);
        core::ser_write_compact_size(s, script_pubkey.size());
        if (!script_pubkey.empty()) {
            core::ser_write_bytes(
                s,
                std::span<const uint8_t>(
                    script_pubkey.data(), script_pubkey.size()));
        }
    }

    /// Deserialize: read amount, then compact-size-prefixed script bytes.
    template<typename Stream>
    static TxOutput deserialize(Stream& s) {
        TxOutput output;
        output.amount = Amount::deserialize(s);

        uint64_t script_len = core::ser_read_compact_size(s);
        output.script_pubkey.resize(static_cast<size_t>(script_len));
        if (script_len > 0) {
            core::ser_read_bytes(
                s,
                std::span<uint8_t>(
                    output.script_pubkey.data(),
                    output.script_pubkey.size()));
        }

        return output;
    }
};

} // namespace primitives
