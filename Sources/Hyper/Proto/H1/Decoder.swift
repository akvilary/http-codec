//===----------------------------------------------------------------------===//
//
//  H1Decoder.swift
//  StarlightServer/H1
//
//  HTTP/1.1 request decoder — port of the hyper::proto::h1 parser
//  pipeline (which itself wraps the `httparse` crate).
//
//  The algorithm is a single-pass byte scanner over an accumulator
//  buffer. Three phases:
//
//    1. Request line: `METHOD SP TARGET SP HTTP/1.1 CRLF`.
//    2. Headers: one per line, `Name: Value CRLF`, terminated by an
//       empty line `CRLF`.
//    3. Body: `Content-Length` bytes (chunked Transfer-Encoding
//       comes in a later phase — same as hyper's default config).
//
//  The decoder is fed bytes incrementally via `feed(_:)`; it returns
//  `.needsMore` when the buffer doesn't yet contain a complete
//  request, `.complete(Request<Body>)` when one is parsed, or throws
//  `H1DecodeError` on malformed input.
//
//  Mirrors hyper::proto::h1::Conn::poll_read_head + httparse::ParserConfig.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Result of a single `feed(_:)` call.
public enum DecodeResult {
    /// The accumulator now contains a complete request.
    case complete(Request<Body>)
    /// More bytes are needed — caller should `read` from the socket
    /// and `feed` again.
    case needsMore
}

/// Errors thrown during decoding. Each maps to a specific HTTP 4xx
/// response when surfaced at the connection layer.
public enum H1DecodeError: Error, Sendable, Equatable {
    /// The request line doesn't fit `METHOD SP TARGET SP HTTP/x.y CRLF`.
    case malformedRequestLine
    /// A header line doesn't fit `Name: Value CRLF`.
    case malformedHeader(line: Int)
    /// The HTTP version string is not `HTTP/1.0` or `HTTP/1.1`.
    case unsupportedVersion(String)
    /// The request exceeds the configured maximum size.
    case requestTooLarge
    /// A `Transfer-Encoding: chunked` request was received.
    /// Phase 1 of axum-arch supports only Content-Length-bounded bodies.
    case chunkedNotSupported
    /// The `Content-Length` header was present but contained a
    /// non-integer, negative, or otherwise invalid value.
    /// RFC 9112 §6.3.6 requires a 400 response.
    case invalidContentLength
    /// Multiple Content-Length headers with conflicting values —
    /// potential HTTP smuggling. RFC 9112 §6.3.6.
    case conflictingContentLength
    /// Too many headers (> `maxHeaderCount`). Header-bomb defence.
    case tooManyHeaders
    /// An empty header name was encountered. RFC 9112 §5.1.
    case emptyHeaderName
}

/// HTTP/1.1 incremental request decoder.
///
/// One instance per connection. `feed(_:)` appends bytes; `decode()`
/// attempts to parse a complete request from the buffered bytes.
/// On success the consumed bytes are discarded from the internal
/// buffer; pipelined requests remain and the next `decode()` call
/// processes them.
///
/// Owned exclusively by the per-connection Task — same role as
/// hyper's single `Conn` per connection. (Phase-2: make `~Copyable`
/// to enforce this at compile time; v0.1 keeps it Copyable so it
/// composes cleanly with `H1Conn<Io>`'s storage.)
public struct H1Decoder: Sendable {
    /// Accumulated bytes, growing as `feed(_:)` is called.
    @usableFromInline internal var buffer: [UInt8] = []
    /// Read cursor — `buffer[0..<parsed]` has been consumed by the
    /// current request, `buffer[parsed..<]` is yet to scan.
    @usableFromInline internal var parsed: Int = 0

    /// Per-instance limits. Mirrors hyper's `h1_max_headers` /
    /// `max_buf_size` settings on a `Conn`.
    public let maxRequestBytes: Int
    public let maxHeaderCount: Int

    public init(maxRequestBytes: Int = 64 * 1024, maxHeaderCount: Int = 100) {
        self.maxRequestBytes = maxRequestBytes
        self.maxHeaderCount = maxHeaderCount
    }

    /// Append incoming bytes from a TCP read.
    @inlinable
    public mutating func feed(_ bytes: [UInt8]) throws {
        if buffer.count + bytes.count > maxRequestBytes {
            buffer.removeAll(keepingCapacity: true)
            parsed = 0
            throw H1DecodeError.requestTooLarge
        }
        buffer.append(contentsOf: bytes)
    }

    /// Append incoming bytes from an unsafe buffer (zero-copy from the
    /// read loop's stack-allocated buffer).
    @inlinable
    public mutating func feed(_ bytes: UnsafeBufferPointer<UInt8>) throws {
        if buffer.count + bytes.count > maxRequestBytes {
            buffer.removeAll(keepingCapacity: true)
            parsed = 0
            throw H1DecodeError.requestTooLarge
        }
        buffer.append(contentsOf: bytes)
    }

    /// Try to parse one complete request from the buffered bytes.
    ///
    /// On success: consumes the parsed bytes from `buffer` and returns
    /// `.complete(request)`. The remaining bytes (if any) are
    /// pipelined requests — caller should call `decode()` again.
    ///
    /// On `.needsMore`: leaves the buffer intact; caller must `feed`
    /// more bytes from the socket.
    public mutating func decode() throws -> DecodeResult {
        // Step 1: scan for the end of the headers block (\r\n\r\n).
        guard let headerEnd = findHeaderBlockEnd() else {
            return .needsMore
        }
        // Step 2: parse request line + headers from buffer[0..<headerEnd].
        let request = try parseRequestHeaders(upTo: headerEnd)
        // Step 3: determine body length, read body bytes if any.
        let bodyEnd = try resolveBodyEnd(headersEnd: headerEnd, request: request)
        guard buffer.count >= bodyEnd else {
            // Headers parsed but body incomplete. Keep state and ask
            // for more bytes — we'll re-parse on the next decode().
            // (A more sophisticated impl would cache the parsed
            //  headers and skip step 1-2 next time; phase-2 polish.)
            return .needsMore
        }
        // Step 4: extract body bytes and finalise Request.
        var finalRequest = request
        if bodyEnd > headerEnd {
            let bodyBytes = Array(buffer[headerEnd..<bodyEnd])
            finalRequest.body = Body(bodyBytes)
        }
        // Step 5: consume parsed bytes, preserving pipelined tail.
        buffer.removeFirst(bodyEnd)
        parsed = 0
        return .complete(finalRequest)
    }

    // MARK: - Internal helpers

    /// Locate the `\r\n\r\n` terminator that closes the header block.
    /// Returns the index *after* the final `\n`, or `nil` if not yet
    /// present in the buffer.
    @inlinable
    internal func findHeaderBlockEnd() -> Int? {
        // The minimum complete request is `GET / HTTP/1.1\r\n\r\n` (16 bytes).
        // We need at least 4 bytes to find any terminator.
        guard buffer.count >= 4 else { return nil }
        var i = parsed
        // Skip ahead by 3 each step because the terminator overlaps
        // 4 positions; checking 1 byte at a time is correct but slower.
        while i + 3 < buffer.count {
            if buffer[i] == 0x0D && buffer[i + 1] == 0x0A
                && buffer[i + 2] == 0x0D && buffer[i + 3] == 0x0A {
                return i + 4
            }
            i &+= 1
        }
        // Tail (last 3 bytes) might be a partial terminator — leave
        // for next feed() to complete.
        return nil
    }

    /// Parse method + target + version + headers from the header block.
    /// Does NOT touch the body.
    @inlinable
    internal func parseRequestHeaders(upTo headerEnd: Int) throws -> Request<Body> {
        var pos = 0
        // ── Request line ────────────────────────────────────────────
        // METHOD SP TARGET SP HTTP/x.y CRLF
        let methodEnd = try findByte(0x20, from: pos, upto: headerEnd)
            ?? { throw H1DecodeError.malformedRequestLine }()
        let method = Method(String(decoding: buffer[pos..<methodEnd], as: UTF8.self))
        pos = methodEnd + 1
        // Skip extra spaces (rare, but RFC-tolerant).
        while pos < headerEnd && buffer[pos] == 0x20 { pos &+= 1 }
        let targetEnd = try findByte(0x20, from: pos, upto: headerEnd)
            ?? { throw H1DecodeError.malformedRequestLine }()
        let targetBytes = Array(buffer[pos..<targetEnd])
        let uri = Uri(bytes: targetBytes)
        pos = targetEnd + 1
        while pos < headerEnd && buffer[pos] == 0x20 { pos &+= 1 }

        // Version: HTTP/1.x CRLF
        guard pos + 10 <= headerEnd,
              buffer[pos] == 0x48, buffer[pos + 1] == 0x54,
              buffer[pos + 2] == 0x54, buffer[pos + 3] == 0x50,
              buffer[pos + 4] == 0x2F,  // "HTTP/"
              buffer[pos + 5] == 0x31,  // '1'
              buffer[pos + 6] == 0x2E   // '.'
        else {
            // Could be HTTP/0.9 or malformed — reject.
            throw H1DecodeError.unsupportedVersion(
                String(decoding: buffer[pos..<min(pos + 10, headerEnd)], as: UTF8.self)
            )
        }
        let minorVersion: UInt8 = buffer[pos + 7]
        let version: Version
        switch minorVersion {
        case 0x30: version = .http10  // '0'
        case 0x31: version = .http11  // '1'
        default:
            throw H1DecodeError.unsupportedVersion(
                "HTTP/1.\(Character(UnicodeScalar(minorVersion)))"
            )
        }
        pos &+= 8  // consumed "HTTP/1.x"
        // Expect CRLF.
        guard pos + 1 < headerEnd,
              buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
        else { throw H1DecodeError.malformedRequestLine }
        pos &+= 2

        // ── Headers ────────────────────────────────────────────────
        var headers = HeaderMap()
        var headerIndex = 0
        var contentLength: Int? = nil
        var contentLengthCount = 0
        var transferEncodingSeen = false

        while pos < headerEnd - 2 {  // stop before final \r\n
            // Empty line means end of headers — but our `headerEnd`
            // already accounts for the terminator, so `pos == headerEnd - 2`
            // is the closing \r\n.
            if buffer[pos] == 0x0D && buffer[pos + 1] == 0x0A { break }

            headerIndex &+= 1
            if headerIndex > maxHeaderCount {
                throw H1DecodeError.tooManyHeaders
            }

            // Header name: bytes up to ':'.
            let nameStart = pos
            while pos < headerEnd && buffer[pos] != 0x3A && buffer[pos] != 0x0D {
                pos &+= 1
            }
            guard pos < headerEnd, buffer[pos] == 0x3A else {
                throw H1DecodeError.malformedHeader(line: headerIndex)
            }
            let nameBytes = buffer[nameStart..<pos]
            if nameBytes.isEmpty {
                throw H1DecodeError.emptyHeaderName
            }
            // Lowercase the name for storage (case-insensitive lookup).
            let name = HeaderName(lowercasedBytes: nameBytes.map {
                (0x41...0x5A).contains($0) ? $0 + 0x20 : $0
            })
            pos &+= 1  // skip ':'
            // Skip optional leading whitespace (RFC 9112 §5.1).
            while pos < headerEnd && (buffer[pos] == 0x20 || buffer[pos] == 0x09) {
                pos &+= 1
            }
            // Value: bytes up to CRLF.
            let valueStart = pos
            while pos < headerEnd - 1 && !(buffer[pos] == 0x0D && buffer[pos + 1] == 0x0A) {
                pos &+= 1
            }
            // Trim trailing whitespace.
            var valueEnd = pos
            while valueEnd > valueStart {
                let prev = buffer[valueEnd - 1]
                if prev == 0x20 || prev == 0x09 { valueEnd &-= 1 } else { break }
            }
            let valueBytes = Array(buffer[valueStart..<valueEnd])
            let value = HeaderValue(bytes: valueBytes)
            headers.append(name, value)

            // Track content-length / transfer-encoding for body parsing.
            // Compare against lowercased ASCII bytes — constant-time-ish.
            if Self.isContentLength(nameBytes) {
                contentLengthCount &+= 1
                guard let n = Int(String(decoding: valueBytes, as: UTF8.self)), n >= 0 else {
                    throw H1DecodeError.invalidContentLength
                }
                if let existing = contentLength, existing != n {
                    throw H1DecodeError.conflictingContentLength
                }
                contentLength = n
            } else if Self.isTransferEncoding(nameBytes) {
                let lower = valueBytes.map {
                    (0x41...0x5A).contains($0) ? $0 + 0x20 : $0
                }
                // Look for "chunked" anywhere in the value (case-insensitive).
                if Self.containsSubstring(lower, pattern: [0x63, 0x68, 0x75, 0x6E, 0x6B, 0x65, 0x64]) {
                    transferEncodingSeen = true
                }
            }

            // Consume CRLF.
            guard pos + 1 < headerEnd,
                  buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
            else { throw H1DecodeError.malformedHeader(line: headerIndex) }
            pos &+= 2
        }

        if transferEncodingSeen {
            // Phase-1: reject chunked. Phase-2 will port hyper's
            // chunked decoder (hyper::proto::h1::decode::Decoder::chunked).
            throw H1DecodeError.chunkedNotSupported
        }

        // Stash the parsed content-length in the request's extensions
        // so resolveBodyEnd() can find it. (A cleaner cut: thread it
        // through the call chain — phase-2 polish.)
        var request = Request<Body>(
            method: method,
            uri: uri,
            version: version,
            headers: headers,
            body: Body()
        )
        if let cl = contentLength {
            request.extensions.insert(ParsedContentLength(length: cl))
        }
        return request
    }

    /// Determine the end offset of the body, given the parsed headers.
    @inlinable
    internal func resolveBodyEnd(headersEnd: Int, request: Request<Body>) throws -> Int {
        // Body length determined by Content-Length only (chunked already
        // rejected above). No Content-Length → no body for requests
        // (RFC 9112 §6.3 — server-side, requests default to no body).
        // HEAD requests never have a body even with Content-Length.
        if request.method == .HEAD {
            return headersEnd
        }
        guard let cl = request.extensions.get(ParsedContentLength.self)?.length else {
            return headersEnd
        }
        return headersEnd + cl
    }

    // MARK: - SWAR-style byte helpers (kept simple for v0.1)

    /// Find `needle` in `buffer[from..<upto]`. Linear scan.
    /// SWAR optimisation lands in phase 2 (port of hyper's
    /// `bytes::Find`).
    @inlinable
    internal func findByte(_ needle: UInt8, from start: Int, upto end: Int) -> Int? {
        var i = start
        while i < end {
            if buffer[i] == needle { return i }
            i &+= 1
        }
        return nil
    }

    /// Case-insensitive ASCII compare against "content-length".
    @inlinable
    internal static func isContentLength(_ name: ArraySlice<UInt8>) -> Bool {
        let expected: [UInt8] = [
            0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D,
            0x6C, 0x65, 0x6E, 0x67, 0x74, 0x68
        ]
        guard name.count == expected.count else { return false }
        var i = 0
        for b in name {
            let lower = (0x41...0x5A).contains(b) ? b + 0x20 : b
            if lower != expected[i] { return false }
            i &+= 1
        }
        return true
    }

    /// Case-insensitive ASCII compare against "transfer-encoding".
    @inlinable
    internal static func isTransferEncoding(_ name: ArraySlice<UInt8>) -> Bool {
        let expected: [UInt8] = [
            0x74, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72, 0x2D,
            0x65, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67
        ]
        guard name.count == expected.count else { return false }
        var i = 0
        for b in name {
            let lower = (0x41...0x5A).contains(b) ? b + 0x20 : b
            if lower != expected[i] { return false }
            i &+= 1
        }
        return true
    }

    /// Naive substring search — used only on header values, which are
    /// short. SWAR lands in phase 2.
    @inlinable
    internal static func containsSubstring(_ haystack: [UInt8], pattern: [UInt8]) -> Bool {
        guard pattern.count <= haystack.count else { return false }
        let lastStart = haystack.count - pattern.count
        for i in 0...lastStart {
            var match = true
            for j in 0..<pattern.count {
                if haystack[i + j] != pattern[j] { match = false; break }
            }
            if match { return true }
        }
        return false
    }
}

/// Extension-scoped carrier for the parsed Content-Length value.
/// Removed from `Request.extensions` once the body has been extracted.
public struct ParsedContentLength: Hashable, Sendable {
    public let length: Int
    @inlinable public init(length: Int) { self.length = length }
}
