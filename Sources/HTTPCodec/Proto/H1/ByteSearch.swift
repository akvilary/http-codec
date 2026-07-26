//===----------------------------------------------------------------------===//
//
//  ByteSearch.swift
//  HTTPCodec/Proto/H1
//
//  SWAR-accelerated byte-search primitives. Port of the technique
//  used by `bytes::Find` (which underlies hyper's parser) and
//  `picohttpparser` (which axum and many other Rust HTTP libraries
//  use for parsing).
//
//  ─── SWAR (SIMD Within A Register) ──────────────────────────────
//
//  The trick: load 8 bytes into a UInt64, XOR with the search byte
//  broadcast to all 8 lanes, then use the "has zero byte" detection
//  to find any zero lane in a single arithmetic op:
//
//      let x = chunk ^ broadcast_pattern        // 0x00 where byte matched
//      let y = (x &- 0x0101...01) & ~x & 0x8080...80
//      // y != 0 ⇔ at least one byte was zero ⇔ at least one match
//
//  On modern x86_64 / arm64 this compiles to ~5 instructions per
//  8-byte chunk vs ~8 instructions for the linear scan. Plus the
//  loop overhead amortises to 1 cmp/jne per 8 bytes (vs 1 per byte).
//
//  Reference:
//    - https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
//    - bits/bytes crate (https://docs.rs/bytes)
//    - picohttpparser (https://github.com/h2o/picohttpparser)
//
//===----------------------------------------------------------------------===//

import Foundation

/// SWAR byte-search primitives. All methods are zero-allocation,
/// `@inline(__always)`, and operate on raw memory for speed.
public enum ByteSearch {

    // MARK: - Single-byte search

    /// Find the first occurrence of `needle` in `buffer[start..<end]`.
    /// Uses SWAR for the bulk; byte-wise for the tail (< 8 bytes).
    ///
    /// Direct port of `bytes::memchr`.
    @inlinable
    @inline(__always)
    public static func findByte(
        _ needle: UInt8,
        in buffer: UnsafeBufferPointer<UInt8>,
        from start: Int,
        to end: Int
    ) -> Int? {
        guard start < end else { return nil }
        var i = start

        // SWAR bulk: process 8 bytes per iteration.
        // We require `i + 8 <= end` so the memcpy doesn't read past end.
        if i + 8 <= end {
            let pattern = UInt64(needle) &* 0x0101_0101_0101_0101
            let base = buffer.baseAddress!
            while i + 8 <= end {
                var chunk: UInt64 = 0
                memcpy(&chunk, base.advanced(by: i), 8)
                #if _endian(big)
                chunk = chunk.byteSwapped
                #endif
                let x = chunk ^ pattern
                // has-zero-byte: ((x - 0x01...) & ~x & 0x80...) != 0
                let y = (x &- 0x0101_0101_0101_0101) & ~x & 0x8080_8080_8080_8080
                if y != 0 {
                    // Found. trailingZeroBitCount gives the bit index of
                    // the lowest set bit; divide by 8 to get byte offset
                    // within the chunk.
                    return i + (y.trailingZeroBitCount / 8)
                }
                i &+= 8
            }
        }

        // Tail: byte-by-byte for the last 0–7 bytes.
        while i < end {
            if buffer[i] == needle { return i }
            i &+= 1
        }
        return nil
    }

    // MARK: - 4-byte sequence search (\r\n\r\n)

    /// Find the first occurrence of `\r\n\r\n` (CRLF CRLF) in
    /// `buffer[start..<end]`. Returns the index *after* the final
    /// `\n`, or `nil` if not present.
    ///
    /// SWAR scans for `\r` candidates 8 bytes at a time; each
    /// candidate is then verified with a 4-byte compare. For typical
    /// HTTP headers (1–4 KB, ~10 `\r` per request), the verify cost
    /// is negligible.
    @inlinable
    @inline(__always)
    public static func findCRLFCRLF(
        in buffer: UnsafeBufferPointer<UInt8>,
        from start: Int,
        to end: Int
    ) -> Int? {
        guard start + 4 <= end else { return nil }
        var i = start

        // SWAR scan for `\r` (0x0D).
        let pattern: UInt64 = 0x0D0D_0D0D_0D0D_0D0D
        let base = buffer.baseAddress!

        while i + 8 <= end {
            var chunk: UInt64 = 0
            memcpy(&chunk, base.advanced(by: i), 8)
            #if _endian(big)
            chunk = chunk.byteSwapped
            #endif
            let x = chunk ^ pattern
            var y = (x &- 0x0101_0101_0101_0101) & ~x & 0x8080_8080_8080_8080

            // Iterate every `\r` candidate in this chunk.
            while y != 0 {
                let byteOffset = y.trailingZeroBitCount / 8
                let pos = i + byteOffset
                if pos + 4 <= end,
                   buffer[pos + 1] == 0x0A,
                   buffer[pos + 2] == 0x0D,
                   buffer[pos + 3] == 0x0A {
                    return pos + 4
                }
                // Clear the lowest set bit and check the next `\r`.
                y &= y &- 1
            }
            i &+= 8
        }

        // Tail: byte-by-byte.
        while i + 4 <= end {
            if buffer[i] == 0x0D,
               buffer[i + 1] == 0x0A,
               buffer[i + 2] == 0x0D,
               buffer[i + 3] == 0x0A {
                return i + 4
            }
            i &+= 1
        }
        return nil
    }

    // MARK: - Two-byte sequence search (\r\n)

    /// Find the first occurrence of `\r\n` (CRLF) in `buffer[start..<end]`.
    /// Returns the index of `\r`, or `nil`.
    @inlinable
    @inline(__always)
    public static func findCRLF(
        in buffer: UnsafeBufferPointer<UInt8>,
        from start: Int,
        to end: Int
    ) -> Int? {
        guard start + 2 <= end else { return nil }
        var i = start

        let pattern: UInt64 = 0x0D0D_0D0D_0D0D_0D0D
        let base = buffer.baseAddress!

        while i + 8 <= end {
            var chunk: UInt64 = 0
            memcpy(&chunk, base.advanced(by: i), 8)
            #if _endian(big)
            chunk = chunk.byteSwapped
            #endif
            let x = chunk ^ pattern
            var y = (x &- 0x0101_0101_0101_0101) & ~x & 0x8080_8080_8080_8080

            while y != 0 {
                let byteOffset = y.trailingZeroBitCount / 8
                let pos = i + byteOffset
                if pos + 2 <= end, buffer[pos + 1] == 0x0A {
                    return pos
                }
                y &= y &- 1
            }
            i &+= 8
        }

        while i + 2 <= end {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A {
                return i
            }
            i &+= 1
        }
        return nil
    }
}
