//===----------------------------------------------------------------------===//
//
//  Encoder.swift
//  HTTPCodec/Proto/H1
//
//  Port of `hyper::proto::h1::Encoder`. Serialises an HTTP/1.1
//  response in two phases:
//
//    1. `encodeHead(...)` — writes status line + headers into the
//       output buffer, decides the body framing (Content-Length /
//       chunked / identity) and returns an `EncodedHead` describing
//       what the caller must do next.
//
//    2. The caller acts on `EncodedHead`:
//         - `.buffered`: writev head + the buffered body bytes.
//         - `.stream`: pull chunks from the body stream and call
//           `encodeChunk(...)` for each, then `encodeEndOfChunks`.
//         - `.streamIdentity(length:)`: pull chunks and write them
//           RAW (no chunk framing) — the user-supplied
//           Content-Length delimits the body; the caller must abort
//           the connection if the stream over- or under-delivers.
//         - `.noBody`: nothing follows the head.
//
//  Mirrors hyper's zero-interpolation design: static parts of the
//  status line and well-known header names are written via direct
//  byte appends; only Content-Length digits are stringified (and for
//  ≤ 4-digit lengths the String fits in a Swift SmallString — 15 bytes).
//
//  Hardening guarantees:
//    - every header name / value is validated BEFORE any of its
//      bytes are written — CRLF injection (response splitting) from
//      a handler is impossible; it fails with `H1EncodeError`.
//      (On throw the buffer may contain earlier valid headers — the
//      caller must reset it before reuse.)
//    - exactly one framing header set reaches the wire, derived from
//      the actual body: a user Content-Length that contradicts a
//      `.buffered` body is an error, not a silent desync.
//    - 1xx / 204 never carry Content-Length or Transfer-Encoding
//      (RFC 9110 §8.6); HEAD preserves the length a GET would have
//      produced (RFC 9110 §9.3.2); a 304's user Content-Length
//      passes verbatim (it describes the selected, unsent
//      representation);
//    - the user's `Connection` header is forwarded verbatim when
//      present (the connection driver folds it into its keep-alive
//      decision via `ServerTransaction.shouldKeepAlive`); otherwise
//      one is generated from the `keepAlive` parameter.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Errors thrown while encoding a response head. All of them are
/// handler-authoring bugs (or a compromised handler) — the connection
/// driver should map them to a 500 + connection close.
public enum H1EncodeError: Error, Sendable, Equatable {
    /// A header name contained bytes that are not RFC 9110 tchar
    /// (e.g. spaces, colons, CR/LF). Response-splitting guard.
    case invalidHeaderName(String)
    /// A header value contained a forbidden control byte (CR, LF,
    /// NUL, …). Response-splitting guard.
    case invalidHeaderValue(name: String)
    /// A user-supplied `Content-Length` was not a bare digit
    /// sequence, or was supplied more than once.
    case invalidContentLength(String)
    /// A user-supplied `Content-Length` contradicted the actual body
    /// size — emitting it would desync the client.
    case contentLengthMismatch(expected: Int, actual: Int)
    /// A user-supplied `Transfer-Encoding` was malformed (not ending
    /// in exactly one `chunked` codeword) or supplied more than once
    /// on a body the encoder wants to stream.
    case invalidTransferEncoding(String)
    /// The handler set more than one `Connection` header — a sender
    /// MUST NOT (RFC 9110 §5.2); contradictory tokens are a bug.
    case duplicateConnection
}

/// Result of `H1Encoder.encodeHead(...)`. Tells the caller what to
/// do with the body next.
public enum EncodedHead: Sendable, Equatable {
    /// The response has no body on the wire (no-body status, empty
    /// body, or a body-less method like HEAD). Write the head, done.
    case noBody
    /// The body is fully materialised in the response (`.buffered`).
    /// It is NOT in the head buffer — use writev to send head + body
    /// in one syscall without concatenation.
    case buffered
    /// The body is streaming with chunked framing: iterate the body
    /// stream, call `encodeChunk(...)` per chunk, then
    /// `encodeEndOfChunks(...)` when done.
    case stream
    /// The body is streaming with identity framing delimited by a
    /// user-supplied `Content-Length` of `length` bytes: write chunks
    /// RAW (never `encodeChunk`). Abort the connection if the stream
    /// produces more than `length` bytes in total or ends before
    /// `length` bytes were written.
    case streamIdentity(length: Int)
}

/// HTTP/1.1 response encoder. Port of `hyper::proto::h1::Encoder`.
public struct H1Encoder: Sendable {

    public struct Config: Sendable {
        /// Emit a `Date` header when the handler didn't set one
        /// (RFC 9110 §6.6.1 SHOULD; cached per second — the format
        /// cost is amortised across every response in the process).
        public var emitDateHeader: Bool = true
        /// Title-case outgoing header names (`content-type` →
        /// `Content-Type`), like hyper's `title_case_headers`.
        public var titleCaseHeaders: Bool = true
        public init(emitDateHeader: Bool = true, titleCaseHeaders: Bool = true) {
            self.emitDateHeader = emitDateHeader
            self.titleCaseHeaders = titleCaseHeaders
        }
    }

    public let config: Config

    @inlinable public init(config: Config = Config()) {
        self.config = config
    }

    // MARK: - Phase 1: encode status + headers

    /// Encode the response status line + headers into `buffer` and
    /// decide the body framing. Does NOT write any body bytes — the
    /// caller sends head + body with writev / streaming per the
    /// returned `EncodedHead`.
    ///
    /// Throws `H1EncodeError` on invalid handler-supplied headers
    /// (non-token names, control bytes in values, contradictory
    /// framing headers). On throw the buffer may contain earlier
    /// valid headers — reset it before reuse.
    ///
    /// - Parameters:
    ///   - requestMethod: method of the request that triggered this
    ///     response. HEAD responses suppress the body (RFC 9110
    ///     §9.3.2) while preserving the Content-Length GET would
    ///     have produced.
    ///   - keepAlive: connection continuation decision from the
    ///     driver (request side folded in via `DecodedHead.keepAlive`,
    ///     response side via `ServerTransaction.shouldKeepAlive`).
    ///     Only used when the handler didn't set `Connection` itself.
    @discardableResult
    public func encodeHead(
        _ response: Response,
        keepAlive: Bool,
        requestMethod: Method = .GET,
        into buffer: inout [UInt8]
    ) throws -> EncodedHead {
        // ── Determine whether the body must be suppressed ─────────
        //
        // RFC 9110 §9.3.2: HEAD responses MUST NOT include a body.
        // RFC 9110 §15.2.1, §15.4.5, §15.4.7: 1xx, 204, 304 responses
        // MUST NOT include a body.
        let isHeadResponse = requestMethod == .HEAD
        let isBodyForbidden = isHeadResponse
            || response.status.code < 200
            || response.status.code == 204
            || response.status.code == 304

        // ── Scan user framing headers BEFORE writing anything ──────
        // Framing headers are never emitted from the generic pass —
        // only the policy below can put exactly one of them on the
        // wire. Duplicates are an error, not a "last one wins".
        var userContentLength: [UInt8]? = nil
        var userContentLengthCount = 0
        var userTransferEncoding: [UInt8]? = nil
        var userTransferEncodingCount = 0
        var userConnectionCount = 0
        var sawDate = false
        for (name, value) in response.headers.entries {
            if name == .contentLength {
                userContentLengthCount &+= 1
                userContentLength = value.bytes
            } else if name == .transferEncoding {
                userTransferEncodingCount &+= 1
                userTransferEncoding = value.bytes
            } else if name == .connection {
                userConnectionCount &+= 1
            } else if name == .date {
                sawDate = true
            }
        }
        if userContentLengthCount > 1 {
            throw H1EncodeError.invalidContentLength("duplicate Content-Length")
        }

        // ── Status line ───────────────────────────────────────────
        writeStatusLine(response.status, into: &buffer)
        buffer.append(contentsOf: Self.crlf)

        // ── Date ──────────────────────────────────────────────────
        if config.emitDateHeader && !sawDate {
            buffer.append(contentsOf: Self.dateNameColonSP)
            buffer.append(contentsOf: Self.dateCache.current())
            buffer.append(contentsOf: Self.crlf)
        }

        // ── Write user headers ────────────────────────────────────
        // Framing + hop-by-hop headers are managed by the encoder
        // itself: Connection is forwarded verbatim (validated),
        // Content-Length / Transfer-Encoding only via the framing
        // policy below. Keep-Alive / TE / Trailer / Proxy-Connection
        // are per-connection concerns a handler must not set — they
        // are dropped. `Upgrade` is deliberately FORWARDED — a 101
        // Switching Protocols response (WebSocket handshake) needs it
        // on the wire. Each header is validated in full BEFORE any
        // of its bytes are written — a rejected header leaves no
        // partial output.
        for (name, value) in response.headers.entries {
            if name == .contentLength || name == .transferEncoding { continue }
            if name == .keepAlive || name == .te
                || name == .trailer || name == .proxyConnection { continue }
            if name == .connection && userConnectionCount > 1 {
                // Multiple Connection headers would each be forwarded;
                // a sender MUST NOT generate them (RFC 9110 §5.2) —
                // contradictory tokens are a handler bug, fail loudly.
                throw H1EncodeError.duplicateConnection
            }
            try validateName(name)
            try value.withUnsafeBytes { try validateValue($0, name: name) }
            writeNameBytes(name, into: &buffer)
            buffer.append(0x3A)
            buffer.append(0x20)
            value.withUnsafeBytes { buffer.append(contentsOf: $0) }
            buffer.append(contentsOf: Self.crlf)
        }

        // ── Framing policy ────────────────────────────────────────
        let encoded: EncodedHead = try framingPolicy(
            body: response.body,
            status: response.status,
            isHeadResponse: isHeadResponse,
            isBodyForbidden: isBodyForbidden,
            userContentLength: userContentLength,
            userTransferEncoding: userTransferEncoding,
            userTransferEncodingCount: userTransferEncodingCount,
            into: &buffer
        )

        // ── Connection ────────────────────────────────────────────
        // The user's own Connection headers were already forwarded in
        // the pass above (verbatim, validated); auto-emit only when
        // the handler didn't set any.
        if userConnectionCount == 0 {
            if response.status.code == 101 {
                // 101 Switching Protocols: the connection is leaving
                // HTTP semantics — `upgrade` is the correct token
                // (RFC 9110 §15.2.2), not keep-alive/close. Covers
                // the handler that set `Upgrade` but forgot
                // `Connection`.
                writeStaticHeader(.connection, value: "upgrade", into: &buffer)
            } else {
                let value = keepAlive ? "keep-alive" : "close"
                writeStaticHeader(.connection, value: value, into: &buffer)
            }
        }

        // ── Empty line separating headers from body ───────────────
        buffer.append(contentsOf: Self.crlf)

        return encoded
    }

    /// Decide and emit `Content-Length` / `Transfer-Encoding`, and
    /// determine the caller's body action. Guarantees exactly one
    /// consistent framing on the wire (or a thrown error).
    private func framingPolicy(
        body: Body,
        status: StatusCode,
        isHeadResponse: Bool,
        isBodyForbidden: Bool,
        userContentLength: [UInt8]?,
        userTransferEncoding: [UInt8]?,
        userTransferEncodingCount: Int,
        into buffer: inout [UInt8]
    ) throws -> EncodedHead {
        switch body {
        case .empty, .pull:
            // `.pull` is request-side only — a handler returning one
            // is a misuse; treat it as an empty body so the wire
            // stays well-formed (Content-Length: 0, no client hang).
            try emitContentLength(
                actualBodyBytes: 0,
                isBodyForbidden: isBodyForbidden,
                isHeadResponse: isHeadResponse,
                status: status,
                userContentLength: userContentLength,
                into: &buffer
            )
            return .noBody

        case .buffered(let bytes):
            try emitContentLength(
                actualBodyBytes: bytes.count,
                isBodyForbidden: isBodyForbidden,
                isHeadResponse: isHeadResponse,
                status: status,
                userContentLength: userContentLength,
                into: &buffer
            )
            if isBodyForbidden { return .noBody }
            return bytes.isEmpty ? .noBody : .buffered

        case .stream:
            if isBodyForbidden {
                // Streaming body on a bodyless status: suppress the
                // body; for HEAD forward a user CL verbatim — it
                // describes the hypothetical GET representation.
                if isHeadResponse, let cl = userContentLength {
                    try emitValidatedContentLength(cl, into: &buffer)
                }
                return .noBody
            }
            if let te = userTransferEncoding {
                // User promised the framing — validate it exactly
                // like the decoder does: exactly one `chunked`, and
                // it must be the final codeword. The value is
                // CTL-validated FIRST: the token analysis below
                // would otherwise accept a CRLF smuggled inside a
                // non-final token (e.g. "gzip\r\nX: y, chunked") and
                // forward it verbatim — a response-splitting vector.
                try te.withUnsafeBufferPointer { try validateValue($0, name: .transferEncoding) }
                if userTransferEncodingCount > 1 {
                    throw H1EncodeError.invalidTransferEncoding("duplicate Transfer-Encoding")
                }
                var chunkedCount = 0
                var lastChunked = false
                TokenList.analyzeTransferEncoding(
                    te, chunkedCount: &chunkedCount, lastTokenChunked: &lastChunked
                )
                if chunkedCount != 1 || !lastChunked {
                    throw H1EncodeError.invalidTransferEncoding(
                        String(decoding: te, as: UTF8.self)
                    )
                }
                // TE wins over CL (RFC 9112 §6.3): any user CL is
                // intentionally dropped. Forward the user's TE.
                writeStaticHeader(.transferEncoding, valueBytes: te, into: &buffer)
                return .stream
            }
            if let cl = userContentLength {
                // User-supplied length with a streaming body:
                // identity framing — the caller writes raw chunks and
                // aborts if the stream over-/under-delivers.
                let length = try parseContentLength(cl)
                if length == 0 { return .noBody }
                emitContentLengthBytes(cl, into: &buffer)
                return .streamIdentity(length: length)
            }
            writeStaticHeader(.transferEncoding, value: "chunked", into: &buffer)
            return .stream
        }
    }

    /// Content-Length policy for length-known bodies (`.empty` /
    /// `.buffered` / `.pull`) — emits (or withholds) the header and
    /// validates the user's value against the actual size.
    ///
    /// - 1xx / 204: no framing header (RFC 9110 §8.6 MUST NOT).
    /// - 304: a user CL passes verbatim (describes the selected,
    ///   unsent representation); no auto CL.
    /// - HEAD: user CL verbatim (unverifiable hypothetical); auto
    ///   CL derived from the actual body otherwise.
    /// - otherwise: user CL must equal the actual size (else throw);
    ///   auto CL otherwise.
    private func emitContentLength(
        actualBodyBytes: Int,
        isBodyForbidden: Bool,
        isHeadResponse: Bool,
        status: StatusCode,
        userContentLength: [UInt8]?,
        into buffer: inout [UInt8]
    ) throws {
        if isBodyForbidden && !isHeadResponse {
            if status.code == 304, let cl = userContentLength {
                try emitValidatedContentLength(cl, into: &buffer)
            }
            return
        }
        if isHeadResponse {
            if let cl = userContentLength {
                try emitValidatedContentLength(cl, into: &buffer)
            } else {
                writeStaticHeader(.contentLength, value: String(actualBodyBytes), into: &buffer)
            }
            return
        }
        if let cl = userContentLength {
            let parsed = try parseContentLength(cl)
            if parsed != actualBodyBytes {
                throw H1EncodeError.contentLengthMismatch(expected: parsed, actual: actualBodyBytes)
            }
            emitContentLengthBytes(cl, into: &buffer)
        } else {
            writeStaticHeader(.contentLength, value: String(actualBodyBytes), into: &buffer)
        }
    }

    // MARK: - Phase 2: streaming body chunks

    /// Write a single chunk to `buffer` in chunked TE format:
    ///
    ///     <hex-size>\r\n
    ///     <bytes>\r\n
    ///
    /// Caller owns the buffer; this just appends.
    public func encodeChunk(_ bytes: [UInt8], into buffer: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        // Hex size — bodies up to ~64 GiB supported via UInt64.
        let hex = String(bytes.count, radix: 16)
        buffer.append(contentsOf: Array(hex.utf8))
        buffer.append(contentsOf: Self.crlf)
        buffer.append(contentsOf: bytes)
        buffer.append(contentsOf: Self.crlf)
    }

    /// Write the terminating zero-length chunk:
    ///
    ///     0\r\n
    ///     \r\n
    ///
    /// Sent after the last data chunk. Optionally includes trailers
    /// (Phase 2 polish — currently no trailers support).
    public func encodeEndOfChunks(into buffer: inout [UInt8]) {
        buffer.append(contentsOf: [0x30])  // '0'
        buffer.append(contentsOf: Self.crlf)
        buffer.append(contentsOf: Self.crlf)
    }

    // MARK: - Status line

    @inline(__always)
    private func writeStatusLine(_ status: StatusCode, into buffer: inout [UInt8]) {
        buffer.append(contentsOf: [
            0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x20
        ])
        let code = status.code
        buffer.append(0x30 + UInt8(code / 100))
        buffer.append(0x30 + UInt8((code / 10) % 10))
        buffer.append(0x30 + UInt8(code % 10))
        buffer.append(0x20)
        buffer.append(contentsOf: Array(status.canonicalReason.utf8))
    }

    // MARK: - Header writing (validated)

    /// Validate a user header name: RFC 9110 tchar only
    /// (response-splitting guard).
    private func validateName(_ name: HeaderName) throws {
        try name.withUnsafeBytes { buf in
            for b in buf where !TokenList.isTokenByte(b) {
                throw H1EncodeError.invalidHeaderName(name.description)
            }
        }
    }

    /// Validate a user header value: SP / HTAB / VCHAR / obs-text
    /// only. Any other control byte (CR, LF, NUL, DEL, …) is a
    /// response-splitting attempt — reject.
    private func validateValue(_ bytes: UnsafeBufferPointer<UInt8>, name: HeaderName) throws {
        for b in bytes {
            let ok = b == 0x20 || b == 0x09 || (0x21...0x7E).contains(b) || b >= 0x80
            if !ok {
                throw H1EncodeError.invalidHeaderValue(name: name.description)
            }
        }
    }

    /// Write a validated name, optionally title-cased.
    private func writeNameBytes(_ name: HeaderName, into buffer: inout [UInt8]) {
        name.withUnsafeBytes { bytes in
            if config.titleCaseHeaders {
                var cap = true
                for b in bytes {
                    if cap && b >= 0x61 && b <= 0x7A {
                        buffer.append(b - 0x20)
                    } else {
                        buffer.append(b)
                    }
                    cap = (b == 0x2D)
                }
            } else {
                buffer.append(contentsOf: bytes)
            }
        }
    }

    private func writeNameBytes(_ bytes: [UInt8], into buffer: inout [UInt8]) {
        if config.titleCaseHeaders {
            var cap = true
            for b in bytes {
                if cap && b >= 0x61 && b <= 0x7A {
                    buffer.append(b - 0x20)
                } else {
                    buffer.append(b)
                }
                cap = (b == 0x2D)
            }
        } else {
            buffer.append(contentsOf: bytes)
        }
    }

    @inline(__always)
    private func writeStaticHeader(_ name: HeaderName, value: String, into buffer: inout [UInt8]) {
        writeNameBytes(name, into: &buffer)
        buffer.append(0x3A)
        buffer.append(0x20)
        buffer.append(contentsOf: value.utf8)
        buffer.append(contentsOf: Self.crlf)
    }

    @inline(__always)
    private func writeStaticHeader(_ name: HeaderName, valueBytes: [UInt8], into buffer: inout [UInt8]) {
        writeNameBytes(name, into: &buffer)
        buffer.append(0x3A)
        buffer.append(0x20)
        buffer.append(contentsOf: valueBytes)
        buffer.append(contentsOf: Self.crlf)
    }

    // MARK: - Content-Length helpers

    /// Parse a user-supplied Content-Length value: bare ASCII digits
    /// only ("+5" / "5 " / garbage → error).
    @inline(__always)
    private func parseContentLength(_ bytes: [UInt8]) throws -> Int {
        guard !bytes.isEmpty else {
            throw H1EncodeError.invalidContentLength("empty")
        }
        var n = 0
        for b in bytes {
            guard b >= 0x30 && b <= 0x39 else {
                throw H1EncodeError.invalidContentLength(
                    String(decoding: bytes, as: UTF8.self)
                )
            }
            let digit = Int(b &- 0x30)
            if n > (Int.max &- digit) / 10 {
                throw H1EncodeError.invalidContentLength("overflow")
            }
            n = n &* 10 &+ digit
        }
        return n
    }

    /// Validate then forward a user Content-Length verbatim (used on
    /// statuses where the value describes something the encoder
    /// cannot verify — HEAD / 304).
    @inline(__always)
    private func emitValidatedContentLength(_ bytes: [UInt8], into buffer: inout [UInt8]) throws {
        _ = try parseContentLength(bytes)
        emitContentLengthBytes(bytes, into: &buffer)
    }

    @inline(__always)
    private func emitContentLengthBytes(_ bytes: [UInt8], into buffer: inout [UInt8]) {
        writeStaticHeader(.contentLength, valueBytes: bytes, into: &buffer)
    }
}

// MARK: - Date header cache

extension H1Encoder {

    @inlinable internal static var crlf: [UInt8] { [0x0D, 0x0A] }
    internal static let dateNameColonSP: [UInt8] = Array("Date: ".utf8)

    /// Process-wide RFC 9110 §6.6.1 IMF-fixdate cache — one locked
    /// tuple, rewritten at most once per second. The lock is
    /// uncontended in practice (held for a compare + array retain).
    internal static let dateCache = HTTPDateCache()
}

/// Caches the wire form of `Date` for the current second.
final class HTTPDateCache: @unchecked Sendable {
    private let lock = NSLock()
    private var second: Int64 = -1
    private var cached: [UInt8] = []

    func current() -> [UInt8] {
        let now = Int64(Date().timeIntervalSince1970)
        lock.lock()
        if now != second {
            second = now
            cached = Self.format(now)
        }
        let out = cached
        lock.unlock()
        return out
    }

    /// Format an epoch-second timestamp as
    /// `Tue, 29 Sep 2026 15:04:05 GMT` — pure integer arithmetic
    /// (Howard Hinnant's `civil_from_days`), no Calendar, no
    /// Locale, no allocation beyond the result.
    static func format(_ t: Int64) -> [UInt8] {
        let days = t / 86_400
        let sod = t % 86_400
        let hour = sod / 3_600
        let minute = (sod % 3_600) / 60
        let second = sod % 60

        let (y, m, d) = civilFromDays(days)
        let weekday = Int((days % 7 + 7 + 4) % 7)  // 1970-01-01 was a Thursday

        let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

        var out = [UInt8]()
        out.reserveCapacity(29)
        out.append(contentsOf: weekdays[weekday].utf8)
        out.append(0x2C)  // ','
        out.append(0x20)  // ' '
        out.append(0x30 + UInt8(d / 10))
        out.append(0x30 + UInt8(d % 10))
        out.append(0x20)
        out.append(contentsOf: months[m - 1].utf8)
        out.append(0x20)
        for digit in String(y).utf8 { out.append(digit) }
        out.append(0x20)
        out.append(0x30 + UInt8(hour / 10))
        out.append(0x30 + UInt8(hour % 10))
        out.append(0x3A)  // ':'
        out.append(0x30 + UInt8(minute / 10))
        out.append(0x30 + UInt8(minute % 10))
        out.append(0x3A)
        out.append(0x30 + UInt8(second / 10))
        out.append(0x30 + UInt8(second % 10))
        out.append(contentsOf: " GMT".utf8)
        return out
    }

    /// Days-since-1970-01-01 → (year, month [1-12], day [1-31]).
    /// Howard Hinnant's `civil_from_days` — exact for the full
    /// Int64 epoch range.
    private static func civilFromDays(_ z0: Int64) -> (Int64, Int, Int) {
        let z = z0 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (m <= 2 ? y + 1 : y, Int(m), Int(d))
    }
}
