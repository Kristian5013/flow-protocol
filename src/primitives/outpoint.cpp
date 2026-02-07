#include "primitives/outpoint.h"

namespace primitives {

std::string OutPoint::to_string() const {
    return txid.to_hex() + ":" + std::to_string(n);
}

} // namespace primitives
