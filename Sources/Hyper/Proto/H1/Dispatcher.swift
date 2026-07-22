//===----------------------------------------------------------------------===//
//
//  Dispatcher.swift
//  Hyper/Proto/H1
//
//  Port of `hyper::proto::h1::dispatch::Dispatcher`. Drives a `Conn`
//  through the read/parse/dispatch/write cycle, calling into a
//  user-provided `Service<Request>` for each request.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// The dispatcher's per-request callback shape. Mirrors
/// `tower::Service<Request, Response = Response>` but kept
/// closure-based for ergonomics — the Starlight layer will wrap
/// any `Service`-conforming type into this closure shape.
public typealias HandleRequest = @Sendable (Request) async throws -> Response

/// Drives an HTTP/1.1 connection through the read/parse/dispatch/write
/// cycle. Direct port of `hyper::proto::h1::dispatch::Dispatcher`.
public struct H1Dispatcher<Io: AsyncReadWrite>: Sendable {
    public let conn: H1Conn<Io>
    public let handler: HandleRequest

    @inlinable
    public init(_ conn: H1Conn<Io>, handler: @escaping HandleRequest) {
        self.conn = conn
        self.handler = handler
    }

    /// Run the connection loop until EOF, error, or shutdown.
    /// Returns when the peer closes the connection or an unrecoverable
    /// error occurs.
    public func run() async throws {
        while conn.state != .closed {
            // Phase 1: read + parse the request head.
            let request = try await readHead()
            guard let request = request else { return }  // graceful EOF
            // Phase 2: body bytes are already consumed by v0.1's
            // buffered decoder. (Phase-3: streaming bodies.)
            // Phase 3: dispatch to the handler.
            let response = try await handler(request)
            // Phase 4: encode + flush the response.
            try await encodeAndFlush(response, keepAlive: conn.keepAlive)

            if !conn.keepAlive { break }
            conn.state = .readingHead
        }

        try await conn.io.shutdown()
        conn.state = .closed
    }

    // MARK: - Phase implementations

    /// Read bytes until the decoder returns `.complete(request)`.
    /// Returns `nil` on graceful EOF (peer closed before sending any
    /// data on a fresh connection).
    private func readHead() async throws -> Request? {
        while true {
            switch try conn.decoder.decode() {
            case .complete(let request):
                let connHeader = request.headers.first(for: .connection)
                conn.keepAlive = Self.shouldKeepAlive(
                    version: request.version,
                    explicitConnection: connHeader
                )
                return request
            case .needsMore:
                let n = try await conn.io.readMore()
                if n == 0 {
                    if conn.io.readBuffer.isEmpty {
                        return nil  // graceful EOF between requests
                    }
                    throw HyperError(.incomplete)
                }
            }
        }
    }

    /// Encode the response and flush to the transport.
    private func encodeAndFlush(
        _ response: Response, keepAlive: Bool
    ) async throws {
        // Phase 1: write status + headers + buffered body (if any).
        let head = conn.encoder.encodeHead(
            response, keepAlive: keepAlive, into: &conn.io.writeBuffer
        )
        // Phase 2: streaming body — write each chunk in chunked TE format.
        if case .stream = head {
            for try await chunk in response.body.dataStream() {
                conn.encoder.encodeChunk(chunk, into: &conn.io.writeBuffer)
                try await conn.io.flush()
            }
            conn.encoder.encodeEndOfChunks(into: &conn.io.writeBuffer)
        }
        try await conn.io.flush()
    }

    /// Static dispatch for keep-alive — mirrors hyper's per-version
    /// default policy.
    @inline(__always)
    private static func shouldKeepAlive(
        version: Version, explicitConnection: HeaderValue?
    ) -> Bool {
        if let conn = explicitConnection {
            let lower = String(decoding: conn.bytes, as: UTF8.self).lowercased()
            if lower.contains("close") { return false }
            if lower.contains("keep-alive") { return true }
        }
        return version == .http11
    }
}
