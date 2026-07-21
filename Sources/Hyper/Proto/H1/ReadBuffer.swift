//===----------------------------------------------------------------------===//
//
//  ReadBuffer.swift
//  Hyper/Proto/H1
//
//  Swift analogue of `bytes::BytesMut` — a growable byte buffer with
//  separate read/write positions. The codec reads from the
//  `[readPos..<writePos]` region; the transport writes into the
//  `[writePos..<capacity]` tail. Zero copy between read(2) and parse.
//
//  ─── Layout ─────────────────────────────────────────────────────
//
//    storage:
//    ┌───────────────────┬──────────────────┬───────────────────┐
//    │  consumed         │  readable        │  writable (tail)  │
//    │  [0..<readPos]    │  [readPos..<wp]  │  [wp..<capacity]  │
//    └───────────────────┴──────────────────┴───────────────────┘
//                         ↑                  ↑
//                       readPos           writePos
//
//  `compact()` moves [readPos..<writePos] to [0..<unread],
//  resetting readPos=0, writePos=unread. Called between reads
//  to reclaim consumed space.
//
//===----------------------------------------------------------------------===//

import Foundation

/// Growable byte buffer with read/write cursors — Swift analogue of
/// Rust's `bytes::BytesMut`.
///
/// One instance per connection. The transport writes into the tail;
/// the codec reads from the readable region. No intermediate copy.
///
/// `@unchecked Sendable` — instances are owned by a single connection
/// Task and never shared across threads. Same model as hyper's
/// `Buffered<T, B>` which owns one `BytesMut` per connection.
public final class ReadBuffer: @unchecked Sendable {
    @usableFromInline internal var storage: UnsafeMutablePointer<UInt8>
    @usableFromInline internal(set) var capacity: Int
    @usableFromInline internal(set) var readPos: Int = 0
    @usableFromInline internal(set) var writePos: Int = 0

    @inlinable public init(capacity: Int = 8192) {
        self.storage = .allocate(capacity: capacity)
        self.capacity = capacity
    }

    deinit { storage.deallocate() }

    // MARK: - Counts

    /// Bytes available for the decoder to parse.
    @inlinable public var readableBytes: Int { writePos - readPos }

    /// Free space at the end for the transport to write into.
    @inlinable public var writableBytes: Int { capacity - writePos }

    /// `true` if no unread bytes remain.
    @inlinable public var isEmpty: Bool { readPos == writePos }

    // MARK: - Write side (transport → buffer)

    /// Mutable pointer to the writable tail. The transport reads(2)
    /// directly into this region — zero copy.
    ///
    /// After writing, call `advanceWritePosition(_:)` to commit.
    @inlinable public var writableTail: UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(
            start: UnsafeMutableRawPointer(storage.advanced(by: writePos)),
            count: writableBytes
        )
    }

    /// Commit `n` bytes as written. Called after read(2) fills
    /// `writableTail`. Mirrors `BytesMut::advance_mut(n)`.
    @inlinable public func advanceWritePosition(_ n: Int) {
        assert(writePos + n <= capacity, "advanceWritePosition overflows capacity")
        writePos += n
    }

    /// Ensure at least `needed` bytes of writable space. Compacts
    /// first; grows if still insufficient.
    public func ensureCapacity(_ needed: Int) {
        if writableBytes >= needed { return }
        compact()
        if writableBytes >= needed { return }
        let newCap = Swift.max(capacity * 2, writePos + needed)
        let newStorage = UnsafeMutablePointer<UInt8>.allocate(capacity: newCap)
        let unread = readableBytes
        if unread > 0 {
            memcpy(newStorage, storage.advanced(by: readPos), unread)
        }
        storage.deallocate()
        storage = newStorage
        capacity = newCap
        readPos = 0
        writePos = unread
    }

    // MARK: - Read side (buffer → decoder)

    /// Immutable pointer to the readable region. The decoder parses
    /// from this view — zero copy.
    @inlinable public var readableBytesPtr: UnsafeBufferPointer<UInt8> {
        UnsafeBufferPointer(start: storage.advanced(by: readPos), count: readableBytes)
    }

    /// Byte access relative to the readable region's start.
    /// `buffer[0]` is the first unread byte.
    @inlinable public subscript(index: Int) -> UInt8 {
        storage[readPos + index]
    }

    /// Slice of the readable region. Returns ArraySlice for
    /// `String(decoding:as:)` compatibility.
    @inlinable public subscript(range: Range<Int>) -> ArraySlice<UInt8> {
        let ptr = readableBytesPtr
        return ArraySlice(ptr[range])
    }

    /// Commit `n` bytes as consumed by the decoder. Mirrors
    /// `BytesMut::advance(n)` on the read side.
    @inlinable public func consume(_ n: Int) {
        assert(readPos + n <= writePos, "consume overflows writePos")
        readPos += n
    }

    // MARK: - Compaction

    /// Move unread bytes to the front, reclaiming consumed space.
    /// Called between reads. O(unread) via memmove.
    ///
    /// For the common case (all bytes consumed): readPos == writePos,
    /// so this resets both to 0 — O(1), no memmove.
    @inlinable public func compact() {
        let unread = readableBytes
        if readPos == 0 { return }
        if unread > 0 {
            memmove(storage, storage.advanced(by: readPos), unread)
        }
        readPos = 0
        writePos = unread
    }

    /// Reset both cursors to 0. Called after a request is fully
    /// consumed and we're ready for the next one.
    @inlinable public func reset() {
        readPos = 0
        writePos = 0
    }

    // MARK: - Debug

    /// Snapshot the readable bytes as `[UInt8]`. For tests/debug only —
    /// allocates a copy.
    public func toReadableArray() -> [UInt8] {
        Array(readableBytesPtr)
    }
}
