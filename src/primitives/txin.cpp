#include "primitives/txin.h"

namespace primitives {

TxInput::TxInput(OutPoint prevout_in, std::vector<uint8_t> script_sig_in,
                 uint32_t sequence_in)
    : prevout(std::move(prevout_in))
    , script_sig(std::move(script_sig_in))
    , sequence(sequence_in) {}

} // namespace primitives
