//===----------------------------------------------------------------------===//
//
//  Server.swift
//  Hyper/Proto/H1
//
//  Port of `hyper::proto::h1::role::Server` (the server-side
//  `Http1Transaction` implementation).
//
//  Provides the server-specific encoding policy: when to send
//  `Connection: close`, how to handle 304/204 (no body), etc.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Server-side HTTP/1.1 transaction policy. Direct port of
/// `hyper::proto::h1::Server` impl of `Http1Transaction`.
public enum ServerTransaction {
    /// Decide whether to keep the connection alive based on the
    /// response status + version + explicit Connection header.
    ///
    /// Mirrors hyper::proto::h1::Server::keep_alive.
    public static func shouldKeepAlive(
        version: Version,
        response: Response,
        explicitConnection: HeaderValue?
    ) -> Bool {
        // 1xx, 204, 304 are bodyless intermediates — keep-alive is fine.
        if response.status.code < 200 { return true }
        if response.status.code == 204 || response.status.code == 304 { return true }

        if let conn = explicitConnection {
            let lower = String(decoding: conn.bytes, as: UTF8.self).lowercased()
            if lower.contains("close") { return false }
            if lower.contains("keep-alive") { return true }
        }
        // Default by HTTP version.
        return version == .http11
    }
}
