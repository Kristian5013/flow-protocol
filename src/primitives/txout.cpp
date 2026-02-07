#include "primitives/txout.h"

namespace primitives {

TxOutput::TxOutput(Amount amount_in, std::vector<uint8_t> script_in)
    : amount(amount_in)
    , script_pubkey(std::move(script_in)) {}

} // namespace primitives
