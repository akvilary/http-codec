//===----------------------------------------------------------------------===//
//
//  HTTP1.swift
//  Hyper/Server/Conn
//
//  Port of `hyper::server::conn::http1::Builder`. High-level
//  convenience for serving HTTP/1.1 over a single accepted connection.
//
//  axum's `serve()` ultimately calls into this — hand it a transport,
//  get back a future that drives the connection until close.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// HTTP/1.1 server connection builder. Port of
/// `hyper::server::conn::http1::Builder`.
public struct HTTP1Builder: Sendable {
    public var maxRequestBytes: Int = 64 * 1024
    public var maxHeaderCount: Int = 100
    public var emitDateHeader: Bool = true

    @inlinable public init() {}

    /// Drive an HTTP/1.1 connection over `transport`, dispatching
    /// each request to `handler`.
    ///
    /// Returns when the connection is closed (peer EOF, error, or
    /// graceful shutdown). Mirrors hyper's
    /// `Builder::serve_connection(io, service)`.
    public func serveConnection<Io: AsyncReadWrite>(
        _ transport: Io,
        handler: @escaping HandleRequest
    ) async throws {
        let decoder = H1Decoder(maxRequestBytes: maxRequestBytes, maxHeaderCount: maxHeaderCount)
        let encoder = H1Encoder(config: H1Encoder.Config())
        let conn = H1Conn(transport, decoder: decoder, encoder: encoder)
        let dispatcher = H1Dispatcher(conn, handler: handler)
        try await dispatcher.run()
    }
}
