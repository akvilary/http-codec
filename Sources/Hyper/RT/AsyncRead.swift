//===----------------------------------------------------------------------===//
//
//  AsyncRead.swift / AsyncWrite.swift
//  Hyper/RT
//
//  Port of `hyper::rt::{Read, Write}`. Async byte-stream traits —
//  what every transport (TCP socket, TLS stream, Unix socket, in-memory
//  test fixture) conforms to.
//
//  In Rust hyper defines these as tokio-style traits. In Swift we use
//  `async`-throwing methods with `UnsafeMutableRawBufferPointer` /
//  `UnsafeRawBufferPointer` for zero-copy byte hand-off — mirroring
//  how tokio's poll_read/poll_write surface raw slices.
//
//===----------------------------------------------------------------------===//

import Foundation

/// Async byte-stream reader — port of `hyper::rt::Read`.
///
/// The transport must be non-blocking: read returns 0 on EOF, throws
/// on error. Implementations include `TcpStream` (epoll-backed) and
/// any test fixture.
public protocol AsyncRead: Sendable {
    /// Attempt to fill `buffer`. Returns the number of bytes actually
    /// read (0 on EOF). The implementation MUST write into the buffer
    /// synchronously w.r.t. its own state — no aliasing of the buffer
    /// after the function returns.
    ///
    /// `buffer` is `inout` so implementations can update the count if
    /// they choose (most don't — they return the count).
    func read(into buffer: UnsafeMutableRawBufferPointer) async throws -> Int
}

/// Async byte-stream writer — port of `hyper::rt::Write`.
public protocol AsyncWrite: Sendable {
    /// Write bytes from `buffer`. Returns the number of bytes actually
    /// written (may be less than `buffer.count` for non-blocking sockets).
    func write(from buffer: UnsafeRawBufferPointer) async throws -> Int

    /// Flush any internally-buffered write. For unbuffered transports
    /// this is a no-op.
    func flush() async throws

    /// Shut down the write half of the stream. After this, further
    /// `write` calls throw.
    func shutdown() async throws
}

/// Convenience: AsyncRead + AsyncWrite in one protocol.
public protocol AsyncReadWrite: AsyncRead, AsyncWrite {}
