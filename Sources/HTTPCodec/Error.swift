//===----------------------------------------------------------------------===//
//
//  Error.swift
//  Hyper
//
//  Port of `hyper::Error`. The errors hyper can produce, classified
//  by where in the codec they originate.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Errors produced by the hyper codec and connection driver.
///
/// Mirrors `hyper::Error` — same classification, same `kind()` accessors.
/// The error is `Sendable` so it can be propagated across Task boundaries
/// (e.g. when the dispatcher catches an IO error and surfaces it to the
/// accept loop).
public struct HTTPCodecError: Error, Sendable, CustomStringConvertible {
    public let kind: Kind
    public let underlying: (any Error & Sendable)?

    @inlinable public init(_ kind: Kind, underlying: (any Error & Sendable)? = nil) {
        self.kind = kind
        self.underlying = underlying
    }

    public enum Kind: Sendable, Equatable {
        /// Parse error while reading a request — malformed request line,
        /// invalid header, chunked decode failure, etc.
        case parse(String)
        /// The client closed the connection mid-message.
        case incomplete
        /// A header read timeout fired before the request was fully
        /// delivered.
        case headerTimeout
        /// A body read timeout fired.
        case bodyTimeout
        /// The connection was reset by the peer.
        case connectionReset
        /// I/O error from the underlying socket.
        case io(errno: Int32)
        /// The request exceeded the configured maximum size.
        case tooLarge
        /// `100-continue` was set but never received.
        case unexpectedContinue
        /// HTTP/2 detected when HTTP/1 was expected (or vice versa).
        case versionMismatch
        /// Internal invariant violated — bug.
        case `internal`
    }

    public var description: String {
        switch kind {
        case .parse(let s):        return "http-codec parse error: \(s)"
        case .incomplete:          return "http-codec: connection closed mid-message"
        case .headerTimeout:       return "http-codec: header read timeout"
        case .bodyTimeout:         return "http-codec: body read timeout"
        case .connectionReset:     return "http-codec: connection reset by peer"
        case .io(let errno):       return "http-codec: I/O error (errno \(errno))"
        case .tooLarge:            return "http-codec: request too large"
        case .unexpectedContinue:  return "http-codec: unexpected 100-continue"
        case .versionMismatch:     return "http-codec: HTTP version mismatch"
        case .internal:            return "http-codec: internal invariant violated"
        }
    }
}

extension HTTPCodecError {
    /// `true` if this error originated from parsing the wire bytes.
    @inlinable public var isParse: Bool {
        if case .parse = kind { return true } else { return false }
    }
    /// `true` if this error is a timeout (header or body).
    @inlinable public var isTimeout: Bool {
        if case .headerTimeout = kind { return true }
        if case .bodyTimeout   = kind { return true }
        return false
    }
    /// `true` if the client closed the connection gracefully.
    @inlinable public var isIncomplete: Bool { kind == .incomplete }
    /// `true` if the I/O layer reported the connection reset.
    @inlinable public var isConnectionReset: Bool { kind == .connectionReset }
}
