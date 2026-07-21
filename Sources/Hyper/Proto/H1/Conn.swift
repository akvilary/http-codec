//===----------------------------------------------------------------------===//
//
//  Conn.swift
//  Hyper/Proto/H1
//
//  Port of `hyper::proto::h1::Conn`. Per-connection HTTP/1.1 driver.
//
//  Owns one `BufferedIO<Io>` + one `H1Decoder` + one `H1Encoder`.
//  Drives the read/parse/dispatch/write cycle for one TCP connection
//  across multiple keep-alive requests.
//
//  Mirrors hyper's `Conn<I, B, T>` — generic over the transport `Io`
//  (which gives us TcpStream, mock sockets, TLS streams, etc.).
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Per-connection state — direct port of hyper::proto::h1::Conn's
/// internal `State` struct, kept minimal for v0.1.
public final class H1Conn<Io: AsyncReadWrite>: @unchecked Sendable {
    public let io: BufferedIO<Io>
    public var decoder: H1Decoder
    public let encoder: H1Encoder

    /// Current connection-level state machine.
    public enum State: Sendable {
        /// Ready to read the next request's headers.
        case readingHead
        /// Headers parsed; reading body bytes.
        case readingBody
        /// Request fully read; response being encoded.
        case writingResponse
        /// Connection closed (graceful EOF or error).
        case closed
    }
    public var state: State = .readingHead

    /// Keep-alive flag for the current request. Updated from
    /// `ServerTransaction.shouldKeepAlive` after parsing.
    public var keepAlive: Bool = true

    @inlinable
    public init(
        _ transport: Io,
        decoder: H1Decoder = H1Decoder(),
        encoder: H1Encoder = H1Encoder()
    ) {
        self.io = BufferedIO(transport)
        self.decoder = decoder
        self.encoder = encoder
    }
}
