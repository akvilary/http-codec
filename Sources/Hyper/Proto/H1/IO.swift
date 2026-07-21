//===----------------------------------------------------------------------===//
//
//  IO.swift
//  Hyper/Proto/H1
//
//  Port of `hyper::proto::h1::io::Buffered`. A read/write buffer
//  wrapper around any `AsyncReadWrite` transport.
//
//  The codec never touches the transport directly — it always goes
//  through `Buffered`, which:
//    * Reads bytes into an internal read buffer (decoupling parser
//      progress from socket read size).
//    * Buffers writes into an internal write buffer (decoupling
//      encoder progress from socket write size).
//    * Drives the flush decision (when to call `write` on the
//      underlying transport).
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Buffered async read/write wrapper around a transport.
/// Port of `hyper::proto::h1::io::Buffered<Io, B>`.
public final class BufferedIO<Io: AsyncReadWrite>: @unchecked Sendable {
    public let transport: Io

    /// Bytes read from the transport, not yet consumed by the decoder.
    public var readBuffer: [UInt8] = []
    /// Bytes produced by the encoder, not yet flushed to the transport.
    public var writeBuffer: [UInt8] = []

    /// Maximum read buffer size — defence against a malicious client
    /// streaming megabytes into the request line. Mirrors hyper's
    /// `max_buf_size`.
    public var maxBufferSize: Int = 8192 * 8

    @inlinable public init(_ transport: Io) {
        self.transport = transport
    }

    /// Read bytes from the transport into `readBuffer`.
    /// Returns the actual number of bytes read (0 on EOF).
    public func readMore() async throws -> Int {
        // Manually-allocated buffer so the pointer can live across
        // the `await` (closures like `withUnsafeMutableBufferPointer`
        // require synchronous bodies). 8 KiB matches the typical MSS.
        let chunk = UnsafeMutableRawBufferPointer.allocate(byteCount: 8192, alignment: 8)
        defer { chunk.deallocate() }
        let n = try await transport.read(into: chunk)
        if n > 0 {
            let typed = chunk.bindMemory(to: UInt8.self)
            let bufPtr = UnsafeBufferPointer(start: typed.baseAddress, count: n)
            readBuffer.append(contentsOf: bufPtr)
        }
        return n
    }

    /// Flush the write buffer to the transport. Returns once all bytes
    /// have been written (or the transport throws).
    public func flush() async throws {
        let pending = writeBuffer
        writeBuffer.removeAll(keepingCapacity: true)
        guard !pending.isEmpty else { return }

        // Manually-allocate so the pointer lives across the await loop.
        let buf = UnsafeMutableRawBufferPointer.allocate(
            byteCount: pending.count, alignment: 8
        )
        defer { buf.deallocate() }
        pending.withUnsafeBufferPointer { src in
            buf.copyMemory(from: UnsafeRawBufferPointer(src))
        }

        var remaining = pending.count
        var offset = 0
        while remaining > 0 {
            let slice = UnsafeRawBufferPointer(
                rebasing: buf[offset..<(offset + remaining)]
            )
            let written = try await transport.write(from: slice)
            if written <= 0 { break }
            remaining -= written
            offset += written
        }
    }

    /// Shut down the transport's write side.
    public func shutdown() async throws {
        try await transport.shutdown()
    }
}
