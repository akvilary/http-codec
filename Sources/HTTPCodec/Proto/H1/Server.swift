//===----------------------------------------------------------------------===//
//
//  Server.swift
//  HTTPCodec/Proto/H1
//
//  Port of `hyper::proto::h1::role::Server` (the server-side
//  `Http1Transaction` implementation).
//
//  Provides the server-specific encoding policy: the keep-alive
//  decision from the response's explicit `Connection` header and the
//  negotiated HTTP version.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTPModel

/// Server-side HTTP/1.1 transaction policy. Direct port of
/// `hyper::proto::h1::Server` impl of `Http1Transaction`.
public enum ServerTransaction {

    private static let close: [UInt8] = Array("close".utf8)

    /// Fold the request-side keep-alive decision with the response's
    /// explicit `Connection` header.
    ///
    /// Semantics — **the request side dominates, the response can
    /// only veto**:
    /// - an explicit `close` token in the response → `false`
    ///   (regardless of status — a 204/304 with `Connection: close`
    ///   means close);
    /// - otherwise the request-side decision stands. `requestKeepAlive`
    ///   is `DecodedHead.keepAlive` — it already encodes the request's
    ///   `Connection` tokens AND the version default, so no version
    ///   default is re-applied here (re-applying it would break
    ///   HTTP/1.0 keep-alive: `1.0 + Connection: keep-alive` must
    ///   survive a response that doesn't mention Connection).
    ///
    /// A `keep-alive` token in the response has no effect on this
    /// decision — it doesn't need to: the encoder forwards the
    /// response's `Connection` verbatim on the wire, which is what
    /// an HTTP/1.0 client needs to see to reuse the connection.
    ///
    /// Token matching is boundary-aware: a value like `closeness`
    /// does not match `close` (a substring check would).
    public static func shouldKeepAlive(
        requestKeepAlive: Bool,
        response: Response,
        explicitConnection: HeaderValue?
    ) -> Bool {
        if let conn = explicitConnection,
           conn.withUnsafeBytes({ TokenList.contains($0, token: close) }) {
            return false
        }
        return requestKeepAlive
    }
}
