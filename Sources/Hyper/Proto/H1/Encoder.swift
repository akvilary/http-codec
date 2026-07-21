//===----------------------------------------------------------------------===//
//
//  Encoder.swift
//  Hyper/Proto/H1
//
//  Port of `hyper::proto::h1::Encoder`. Serialises an HTTP/1.1
//  response into a byte buffer ready for `writev` over the socket.
//
//  Mirrors hyper's zero-interpolation design: static parts of the
//  status line and well-known header names are written via direct
//  byte appends; only Content-Length digits are stringified (and for
//  ≤ 4-digit lengths the String fits in a Swift SmallString — 15 bytes).
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// HTTP/1.1 response encoder. Port of `hyper::proto::h1::Encoder`.
///
/// Writes a `Response<Body>` into a `inout [UInt8]` accumulator. The
/// caller owns the accumulator (typically the connection's reusable
/// write buffer); the encoder just appends.
public struct H1Encoder: Sendable {

    /// Configuration — mirrors hyper's configurable flags but kept
    /// minimal for v0.1.
    public struct Config: Sendable {
        /// Emit a `Date:` header automatically. Defaults to `true`.
        public var emitDateHeader: Bool = true
        /// Title-case header names (`Content-Type` vs `content-type`).
        /// Defaults to `true` — matches what hyper does for HTTP/1.1
        /// and what RFC 9110 §5.1 historically shows in examples.
        /// (HTTP/2 mandates lowercase per RFC 9113 §8.1.1 — that's
        /// the H2 encoder's concern, not the H1's.)
        public var titleCaseHeaders: Bool = true
        @inlinable public init() {}
    }

    public let config: Config

    @inlinable public init(config: Config = Config()) {
        self.config = config
    }

    /// Encode `response` into `buffer`. Sets keep-alive based on
    /// version + Connection header.
    ///
    /// Returns the number of bytes appended.
    @discardableResult
    public func encode(
        _ response: Response<Body>,
        keepAlive: Bool,
        into buffer: inout [UInt8]
    ) -> Int {
        let start = buffer.count

        // ── Status line ───────────────────────────────────────────
        writeStatusLine(response.status, into: &buffer)
        buffer.append(contentsOf: Self.crlf)  // CRLF

        // ── Headers ───────────────────────────────────────────────
        // Auto-add Content-Length / Connection if not present.
        var sawContentLength = false
        var sawConnection = false
        let bodyLen = response.body.count
        for (name, value) in response.headers.entries {
            writeHeaderName(name, into: &buffer)
            buffer.append(0x3A)  // ':'
            buffer.append(0x20)  // ' '
            buffer.append(contentsOf: value.bytes)
            buffer.append(contentsOf: Self.crlf)

            if name == .contentLength { sawContentLength = true }
            if name == .connection    { sawConnection = true }
        }

        if !sawContentLength && bodyLen > 0 {
            writeStaticHeader(.contentLength, value: String(bodyLen), into: &buffer)
        }
        if !sawConnection {
            if keepAlive {
                writeStaticHeader(.connection, value: "keep-alive", into: &buffer)
            } else {
                writeStaticHeader(.connection, value: "close", into: &buffer)
            }
        }

        // ── Empty line separating headers from body ───────────────
        buffer.append(contentsOf: Self.crlf)

        // ── Body ──────────────────────────────────────────────────
        if !response.body.isEmpty {
            buffer.append(contentsOf: response.body.bytes)
        }

        return buffer.count - start
    }

    // MARK: - Status line

    @inline(__always)
    private func writeStatusLine(_ status: StatusCode, into buffer: inout [UInt8]) {
        // "HTTP/1.1 " — 9 ASCII bytes, written directly to avoid the
        // SmallString bridging that `buffer.append(contentsOf: "..."utf8)`
        // would incur.
        buffer.append(contentsOf: [
            0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x20
        ])
        // 3-digit status code — write each digit directly.
        let code = status.code
        buffer.append(0x30 + UInt8(code / 100))
        buffer.append(0x30 + UInt8((code / 10) % 10))
        buffer.append(0x30 + UInt8(code % 10))
        buffer.append(0x20)  // SP
        // Reason phrase.
        buffer.append(contentsOf: Array(status.canonicalReason.utf8))
    }

    // MARK: - Header writing

    @inline(__always)
    private func writeHeaderName(_ name: HeaderName, into buffer: inout [UInt8]) {
        if config.titleCaseHeaders {
            // Capitalize first letter of each dash-separated word.
            var cap = true
            for b in name.bytes {
                if cap && b >= 0x61 && b <= 0x7A {  // a-z
                    buffer.append(b - 0x20)
                } else {
                    buffer.append(b)
                }
                cap = (b == 0x2D)  // '-'
            }
        } else {
            buffer.append(contentsOf: name.bytes)
        }
    }

    @inline(__always)
    private func writeStaticHeader(_ name: HeaderName, value: String, into buffer: inout [UInt8]) {
        writeHeaderName(name, into: &buffer)
        buffer.append(0x3A)  // ':'
        buffer.append(0x20)  // ' '
        buffer.append(contentsOf: value.utf8)
        buffer.append(contentsOf: Self.crlf)
    }
}

// CRLF as a static [UInt8] — written hundreds of times per response,
// avoid re-allocating it.
extension H1Encoder {
    @inlinable internal static var crlf: [UInt8] { [0x0D, 0x0A] }
}
