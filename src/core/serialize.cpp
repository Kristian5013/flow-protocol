// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/serialize.h"

// ---------------------------------------------------------------------------
// Non-template / non-inline helpers for the serialization framework.
//
// The vast majority of the serialization API consists of templates and inline
// functions defined in serialize.h.  This translation unit provides:
//
//   1. A compilation-unit anchor so the linker always sees this TU (the
//      CMakeLists.txt already references serialize.cpp).
//
//   2. Explicit template instantiations for the three concrete stream types
//      (DataStream, VectorWriter, SpanReader) to speed up builds and verify
//      that the templates compile cleanly for every stream.
// ---------------------------------------------------------------------------

namespace core {

// -------------------------------------------------------------------
// Explicit instantiations -- CompactSize
// -------------------------------------------------------------------
template void     ser_write_compact_size<DataStream>(
    DataStream&, uint64_t);
template uint64_t ser_read_compact_size<DataStream>(DataStream&);

template void     ser_write_compact_size<VectorWriter>(
    VectorWriter&, uint64_t);
template uint64_t ser_read_compact_size<SpanReader>(SpanReader&);

// -------------------------------------------------------------------
// Explicit instantiations -- primitive writers (DataStream)
// -------------------------------------------------------------------
template void ser_write_u8<DataStream>(DataStream&, uint8_t);
template void ser_write_u16<DataStream>(DataStream&, uint16_t);
template void ser_write_u32<DataStream>(DataStream&, uint32_t);
template void ser_write_u64<DataStream>(DataStream&, uint64_t);
template void ser_write_i32<DataStream>(DataStream&, int32_t);
template void ser_write_i64<DataStream>(DataStream&, int64_t);
template void ser_write_bytes<DataStream>(
    DataStream&, std::span<const uint8_t>);

// -------------------------------------------------------------------
// Explicit instantiations -- primitive readers (DataStream)
// -------------------------------------------------------------------
template uint8_t  ser_read_u8<DataStream>(DataStream&);
template uint16_t ser_read_u16<DataStream>(DataStream&);
template uint32_t ser_read_u32<DataStream>(DataStream&);
template uint64_t ser_read_u64<DataStream>(DataStream&);
template int32_t  ser_read_i32<DataStream>(DataStream&);
template int64_t  ser_read_i64<DataStream>(DataStream&);
template void     ser_read_bytes<DataStream>(
    DataStream&, std::span<uint8_t>);

// -------------------------------------------------------------------
// Explicit instantiations -- primitive writers (VectorWriter)
// -------------------------------------------------------------------
template void ser_write_u8<VectorWriter>(VectorWriter&, uint8_t);
template void ser_write_u16<VectorWriter>(VectorWriter&, uint16_t);
template void ser_write_u32<VectorWriter>(VectorWriter&, uint32_t);
template void ser_write_u64<VectorWriter>(VectorWriter&, uint64_t);
template void ser_write_i32<VectorWriter>(VectorWriter&, int32_t);
template void ser_write_i64<VectorWriter>(VectorWriter&, int64_t);
template void ser_write_bytes<VectorWriter>(
    VectorWriter&, std::span<const uint8_t>);

// -------------------------------------------------------------------
// Explicit instantiations -- primitive readers (SpanReader)
// -------------------------------------------------------------------
template uint8_t  ser_read_u8<SpanReader>(SpanReader&);
template uint16_t ser_read_u16<SpanReader>(SpanReader&);
template uint32_t ser_read_u32<SpanReader>(SpanReader&);
template uint64_t ser_read_u64<SpanReader>(SpanReader&);
template int32_t  ser_read_i32<SpanReader>(SpanReader&);
template int64_t  ser_read_i64<SpanReader>(SpanReader&);
template void     ser_read_bytes<SpanReader>(
    SpanReader&, std::span<uint8_t>);

// -------------------------------------------------------------------
// Explicit instantiations -- string (DataStream)
// -------------------------------------------------------------------
template void        ser_write_string<DataStream>(
    DataStream&, std::string_view);
template std::string ser_read_string<DataStream>(DataStream&);

template void        ser_write_string<VectorWriter>(
    VectorWriter&, std::string_view);
template std::string ser_read_string<SpanReader>(SpanReader&);

// -------------------------------------------------------------------
// Explicit instantiations -- byte vector (DataStream)
// -------------------------------------------------------------------
template void ser_write_vector<DataStream>(
    DataStream&, const std::vector<uint8_t>&);
template std::vector<uint8_t> ser_read_vector<DataStream>(
    DataStream&);

template void ser_write_vector<VectorWriter>(
    VectorWriter&, const std::vector<uint8_t>&);
template std::vector<uint8_t> ser_read_vector<SpanReader>(
    SpanReader&);

// -------------------------------------------------------------------
// Explicit instantiations -- bool (DataStream)
// -------------------------------------------------------------------
template void ser_write_bool<DataStream>(DataStream&, bool);
template bool ser_read_bool<DataStream>(DataStream&);

// -------------------------------------------------------------------
// Explicit instantiations -- uint256 / uint160 (DataStream)
// -------------------------------------------------------------------
template void         ser_write_uint256<DataStream>(
    DataStream&, const core::uint256&);
template core::uint256 ser_read_uint256<DataStream>(DataStream&);

template void         ser_write_uint160<DataStream>(
    DataStream&, const core::uint160&);
template core::uint160 ser_read_uint160<DataStream>(DataStream&);

// -------------------------------------------------------------------
// Explicit instantiations -- varint for the three stream types
// -------------------------------------------------------------------
template void     write_varint<DataStream>(DataStream&, uint64_t);
template uint64_t read_varint<DataStream>(DataStream&);

template void     write_varint<VectorWriter>(
    VectorWriter&, uint64_t);
template uint64_t read_varint<SpanReader>(SpanReader&);

}  // namespace core
