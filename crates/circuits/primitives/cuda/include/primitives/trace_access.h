#pragma once

#include "fp.h"
#include <cstddef>

/// Compute col-major offset with forced 64-bit multiplication.
/// Prevents nvcc/hipcc strength-reduction bugs that corrupt addresses
/// on wide traces (e.g. 903 cols × 2M rows × 4 bytes = 7 GB).
/// Use this for any device-code `col * stride` that bypasses RowSlice.
__device__ __forceinline__ size_t trace_col_offset(size_t col, size_t stride) {
    return static_cast<uint64_t>(col) * static_cast<uint64_t>(stride);
}

/// A RowSlice is a contiguous section of a row in col-based trace.
struct RowSlice {
    Fp *ptr;
    size_t stride;

    __device__ RowSlice(Fp *ptr, size_t stride) : ptr(ptr), stride(stride) {}

    // Force 64-bit multiplication to prevent nvcc/hipcc strength-reduction bugs
    // that corrupt wide-trace addresses (e.g. 903 cols × 2M rows × 4 = 7 GB).
    // See https://github.com/stephenh-axiom-xyz/cuda-illegal.
    __device__ __forceinline__ size_t col_offset(size_t col) const {
        return static_cast<uint64_t>(col) * static_cast<uint64_t>(stride);
    }

    __device__ __forceinline__ Fp &operator[](size_t column_index) const {
        return ptr[col_offset(column_index)];
    }

    __device__ static RowSlice null() { return RowSlice(nullptr, 0); }

    __device__ bool is_valid() const { return ptr != nullptr; }

    template <typename T>
    __device__ __forceinline__ void write(size_t column_index, T value) const {
        ptr[col_offset(column_index)] = value;
    }

    template <typename T>
    __device__ __forceinline__ void write_array(
        size_t column_index,
        size_t length,
        const T *values
    ) const {
#pragma unroll
        for (size_t i = 0; i < length; i++) {
            ptr[col_offset(column_index + i)] = values[i];
        }
    }

    template <typename T>
    __device__ __forceinline__ void write_bits(size_t column_index, const T value) const {
#pragma unroll
        for (size_t i = 0; i < sizeof(T) * 8; i++) {
            ptr[col_offset(column_index + i)] = (value >> i) & 1;
        }
    }

    __device__ __forceinline__ void fill_zero(size_t column_index_from, size_t length) const {
#pragma unroll
        for (size_t i = 0, c = column_index_from; i < length; i++, c++) {
            ptr[col_offset(c)] = 0;
        }
    }

    __device__ __forceinline__ RowSlice slice_from(size_t column_index) const {
        return RowSlice(ptr + col_offset(column_index), stride);
    }

    __device__ __forceinline__ RowSlice shift_row(size_t n) const {
        return RowSlice(ptr + n, stride);
    }
};

/// Compute the 0-based column index of member `FIELD` within struct template `STRUCT<T>`,
/// by instantiating it as `STRUCT<uint8_t>` so that offsetof yields the element index.
#define COL_INDEX(STRUCT, FIELD) (offsetof(STRUCT<uint8_t>, FIELD))

/// Compute the fixed array length of `FIELD` within `STRUCT<T>`
#define COL_ARRAY_LEN(STRUCT, FIELD) (sizeof(static_cast<STRUCT<uint8_t> *>(nullptr)->FIELD))

/// Write a single value into `FIELD` of struct `STRUCT<T>` at a given row.
#define COL_WRITE_VALUE(ROW, STRUCT, FIELD, VALUE) (ROW).write(COL_INDEX(STRUCT, FIELD), VALUE)

/// Write an array of values into the fixed‐length `FIELD` array of `STRUCT<T>` for one row.
#define COL_WRITE_ARRAY(ROW, STRUCT, FIELD, VALUES)                                                \
    (ROW).write_array(COL_INDEX(STRUCT, FIELD), COL_ARRAY_LEN(STRUCT, FIELD), VALUES)

/// Write a single value bits into `FIELD` of struct `STRUCT<T>` at a given row.
#define COL_WRITE_BITS(ROW, STRUCT, FIELD, VALUE) (ROW).write_bits(COL_INDEX(STRUCT, FIELD), VALUE)

/// Fill entire `FIELD` of `STRUCT<T>` with zeros.
#define COL_FILL_ZERO(ROW, STRUCT, FIELD)                                                          \
    (ROW).fill_zero(                                                                               \
        COL_INDEX(STRUCT, FIELD), sizeof(static_cast<STRUCT<uint8_t> *>(nullptr)->FIELD)           \
    )
