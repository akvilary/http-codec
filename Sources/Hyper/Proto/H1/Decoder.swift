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
//  request, `.complete(Request)` when one is parsed, or throws
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
    case complete(Request)
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
    /// A `Transfer-Encoding: chunked` request body was malformed.
    /// Mirrors `hyper::Error::new_body_write_aborted` for decode failures.
    case malformedChunkSize
    case malformedChunkData
    /// A chunked body needs more bytes — the buffer doesn't yet contain
    /// the terminating 0-chunk. Caller should `feed` more and retry.
    case incompleteChunkedBody
    /// A header value contained a bare CR (0x0D) or LF (0x0A) that is
    /// not part of a CRLF pair. RFC 9112 §5.1 forbids this; accepting
    /// it enables header-injection / request-smuggling attacks.
    case bareCrLfInHeader(line: Int)
    /// An HTTP/1.1 request without a Host header. RFC 9112 §3.2
    /// mandates that a server MUST respond 400.
    case missingHost
    /// Both `Content-Length` and `Transfer-Encoding: chunked` were
    /// present. RFC 9112 §6.3.6 permits resolving this in favour of
    /// chunked, but modern secure implementations reject with 400
    /// because the disagreement between stacks is the root cause of
    /// CL.TE / TE.CL request smuggling.
    case conflictingFraming
}

/// HTTP/1.1 incremental request decoder.
///
/// One instance per connection. `feed(_:)` appends bytes; `decode()`
/// attempts to parse a complete request from the buffered bytes.
/// On success the consumed bytes are discarded from the internal
/// buffer; pipelined requests remain and the next `decode()` call
/// processes them.
///
/// Uses `[UInt8]` as the backing store — clean Sendable, no
/// @unchecked, no ARC overhead. The Reactor (PollEventLoop) owns
/// the raw read buffer and feeds bytes via `feed(_:)`.
public struct H1Decoder: Sendable {
    /// Accumulated unparsed bytes.
    @usableFromInline internal var buffer: [UInt8] = []

    /// Reusable HeaderMap — cleared and repopulated per request.
    @usableFromInline internal var reusableHeaders = HeaderMap()

    /// Reusable Extensions — cleared and repopulated per request.
    @usableFromInline internal var reusableExtensions = Extensions()

    public let maxRequestBytes: Int
    public let maxHeaderCount: Int
    public let maxBodyBytes: Int

    public init(
        maxRequestBytes: Int = 64 * 1024,
        maxHeaderCount: Int = 100,
        maxBodyBytes: Int = 2 * 1024 * 1024  // 2 MB, matching DefaultBodyLimit
    ) {
        self.maxRequestBytes = maxRequestBytes
        self.maxHeaderCount = maxHeaderCount
        self.maxBodyBytes = maxBodyBytes
    }

    // MARK: - Feed

    /// Append incoming bytes from a TCP read.
    @inlinable
    public mutating func feed(_ bytes: [UInt8]) throws {
        if buffer.count + bytes.count > maxRequestBytes {
            buffer.removeAll(keepingCapacity: true)
            throw H1DecodeError.requestTooLarge
        }
        buffer.append(contentsOf: bytes)
    }

    /// Append incoming bytes from an unsafe buffer pointer.
    /// One memcpy (~10ns for 100 bytes). The Reactor provides the
    /// pointer from its internal raw buffer.
    @inlinable
    public mutating func feed(_ bytes: UnsafeBufferPointer<UInt8>) throws {
        if buffer.count + bytes.count > maxRequestBytes {
            buffer.removeAll(keepingCapacity: true)
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
        guard let request = try parseRequestHeaders(upTo: headerEnd) else {
            return .needsMore
        }
        // Step 3: determine body length, read body bytes if any.
        let bodyEnd = try resolveBodyEnd(headersEnd: headerEnd, request: request)
        guard buffer.count >= bodyEnd else {
            return .needsMore
        }
        // Step 4: extract body bytes and finalise Request.
        var finalRequest = request
        if bodyEnd > headerEnd {
            let bodyBytes = Array(buffer[headerEnd..<bodyEnd])
            finalRequest.body = .buffered(bodyBytes)
        }
        // Step 5: consume parsed bytes. removeFirst preserves
        // backing storage capacity for keep-alive reuse.
        let totalConsumed = finalRequest.extensions.get(ChunkedBytesConsumed.self)?.value ?? bodyEnd
        buffer.removeFirst(totalConsumed)
        return .complete(finalRequest)
    }

    // MARK: - Internal helpers

    /// Locate the `\r\n\r\n` terminator that closes the header block.
    /// Returns the index *after* the final `\n`, or `nil` if not yet
    /// present in the buffer.
    ///
    /// Uses SWAR-accelerated `ByteSearch.findCRLFCRLF` — scans for `\r`
    /// candidates 8 bytes at a time, then verifies each. ~5× faster
    /// than byte-by-byte on typical HTTP header blocks.
    @inlinable
    internal func findHeaderBlockEnd() -> Int? {
        guard buffer.count >= 4 else { return nil }
        return buffer.withUnsafeBufferPointer { ptr in
            ByteSearch.findCRLFCRLF(in: ptr, from: 0, to: buffer.count)
        }
    }

    /// Parse method + target + version + headers from the header block.
    /// Does NOT touch the body.
    @inlinable
    internal mutating func parseRequestHeaders(upTo headerEnd: Int) throws -> Request? {
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
        // Reuse the per-decoder HeaderMap — clear entries but
        // preserve backing array capacity. Avoids array allocation
        // per keep-alive request (matches hyper's cached_headers).
        reusableHeaders.entries.removeAll(keepingCapacity: true)
        var headerIndex = 0
        var contentLength: Int? = nil
        var contentLengthCount = 0
        var transferEncodingSeen = false
        var seenHost = false  // tracked inline — avoids post-parse scan

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
            // Value: scan byte-by-byte until CRLF. Reject bare CR or LF
            // inline (RFC 9112 §5.1) — this is the smuggling guard. For
            // well-formed traffic the extra branch is predicted not-taken
            // and costs ~0 cycles; it replaces a separate O(n) pass.
            let valueStart = pos
            scanLoop: while pos < headerEnd - 1 {
                let b = buffer[pos]
                if b == 0x0D {
                    if buffer[pos + 1] == 0x0A { break scanLoop }  // CRLF — end
                    throw H1DecodeError.bareCrLfInHeader(line: headerIndex)  // bare CR
                }
                if b == 0x0A {
                    throw H1DecodeError.bareCrLfInHeader(line: headerIndex)  // bare LF
                }
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
            reusableHeaders.append(name, value)

            // Track content-length / transfer-encoding / host for body
            // parsing + HTTP/1.1 compliance. Compared inline during the
            // existing scan — zero extra passes over the header set.
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
                // RFC 9112 §7.2.1: chunked must be the LAST codeword
                // in the Transfer-Encoding list. Split on comma, trim
                // OWS per element, compare last token case-insensitively
                // against "chunked". This rejects "xchunked",
                // "chunked-experimental", etc.
                //
                // Performance: the lowercased value is already a small
                // array (typically "chunked" alone). The comma-split
                // loop touches each byte once — same order as the old
                // substring search, but with exact matching.
                let lower = valueBytes.map {
                    (0x41...0x5A).contains($0) ? $0 + 0x20 : $0
                }
                // Find the last comma — everything after it is the
                // last codeword.
                var lastComma: Int? = nil
                for i in 0..<lower.count where lower[i] == 0x2C {  // ','
                    lastComma = i
                }
                let tokenStart = (lastComma ?? -1) + 1
                // Trim trailing OWS (0x20 / 0x09) from the token.
                var tokenEnd = lower.count
                while tokenEnd > tokenStart && (lower[tokenEnd - 1] == 0x20 || lower[tokenEnd - 1] == 0x09) {
                    tokenEnd &-= 1
                }
                // Also trim leading OWS after the comma.
                var s = tokenStart
                while s < tokenEnd && (lower[s] == 0x20 || lower[s] == 0x09) {
                    s &+= 1
                }
                // Exact compare against "chunked" (7 bytes).
                let chunked: [UInt8] = [0x63, 0x68, 0x75, 0x6E, 0x6B, 0x65, 0x64]
                if tokenEnd - s == chunked.count {
                    var match = true
                    for i in 0..<chunked.count where lower[s + i] != chunked[i] {
                        match = false; break
                    }
                    if match { transferEncodingSeen = true }
                }
            } else if !seenHost && Self.isHost(nameBytes) {
                seenHost = true
            }

            // Consume CRLF.
            guard pos + 1 < headerEnd,
                  buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
            else { throw H1DecodeError.malformedHeader(line: headerIndex) }
            pos &+= 2
        }

        // ── HTTP/1.1 Host header check (RFC 9112 §3.2) ──────────────
        // Tracked inline during the header loop — no post-parse scan.
        if version == .http11 && !seenHost {
            throw H1DecodeError.missingHost
        }

        // ── Body framing selection ─────────────────────────────────
        //
        // Reject CL + TE conflict outright (RFC 9112 §6.3.6 permits
        // chunked preference, but the disagreement between stacks is
        // the root of CL.TE / TE.CL request smuggling). This matches
        // the posture of modern secure HTTP implementations.
        if transferEncodingSeen && contentLength != nil {
            throw H1DecodeError.conflictingFraming
        }

        if transferEncodingSeen {
            // Parse the body as chunked Transfer-Encoding
            // (RFC 9112 §7.1). Each chunk is:
            //
            //   <hex-size>[;extensions]\r\n
            //   <size bytes>\r\n
            //
            // Terminated by a zero-size chunk:
            //
            //   0\r\n\r\n
            //
            // For v0.1 we buffer all chunks into a single Body.buffered
            // (matches axum's default behavior when an extractor calls
            // `to_bytes(body, limit)`). True streaming request body
            // (Body.stream from a chunked source) is phase-2 polish.
            do {
                let (chunkedBytes, consumedPos) = try parseChunkedBody(
                    headerEnd: headerEnd, headerIndex: headerIndex
                )
                reusableExtensions.removeAll()
                var request = Request(
                    method: method,
                    uri: uri,
                    version: version,
                    headers: reusableHeaders,
                    body: .buffered(chunkedBytes),
                    extensions: reusableExtensions
                )
                request.extensions.insert(ChunkedBytesConsumed(consumedPos))
                return request
            } catch H1DecodeError.incompleteChunkedBody {
                // Body not yet fully in the buffer — caller should
                // feed more bytes and retry. Propagate as nil so the
                // outer decode() returns .needsMore.
                return nil
            }
        }

        // Reuse Extensions — clear storage but preserve capacity.
        reusableExtensions.removeAll()

        var request = Request(
            method: method,
            uri: uri,
            version: version,
            headers: reusableHeaders,
            body: .empty,
            extensions: reusableExtensions
        )
        if let cl = contentLength {
            request.extensions.insert(ParsedContentLength(length: cl))
        }
        return request
    }

    /// Determine the end offset of the body, given the parsed headers.
    @inlinable
    internal func resolveBodyEnd(headersEnd: Int, request: Request) throws -> Int {
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

    /// Parse a chunked Transfer-Encoding body. Direct port of
    /// `hyper::proto::h1::decode::Decoder::chunked` (simplified —
    /// we buffer all chunks into memory rather than streaming).
    ///
    /// Grammar (RFC 9112 §7.1):
    ///
    ///     chunk          = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
    ///     chunk-size     = 1*HEXDIG
    ///     chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
    ///     chunk-data     = 1*OCTET  ; a sequence of chunk-size octets
    ///     last-chunk     = 1*("0") [ chunk-ext ] CRLF
    ///     trailer-part   = *( header-field CRLF )
    ///     CRLF           = CR LF
    ///
    /// Returns the buffered body bytes. Throws on malformed input or
    /// if the buffer doesn't yet contain the full chunked body — the
    /// caller should `feed` more bytes and retry in the latter case.
    @usableFromInline
    internal func parseChunkedBody(headerEnd: Int, headerIndex: Int) throws -> (bytes: [UInt8], consumed: Int) {
        var pos = headerEnd
        var body: [UInt8] = []

        chunkLoop: while pos < buffer.count {
            // ── Read hex chunk size ──────────────────────────────
            let sizeStart = pos
            while pos < buffer.count && buffer[pos] != 0x0D && buffer[pos] != 0x3B {
                pos &+= 1  // scan until CR or ';' (chunk-ext)
            }
            guard pos < buffer.count else {
                throw H1DecodeError.incompleteChunkedBody
            }
            // Parse hex size.
            let sizeBytes = buffer[sizeStart..<pos]
            guard !sizeBytes.isEmpty,
                  let chunkSize = Self.parseHex(sizeBytes)
            else {
                throw H1DecodeError.malformedChunkSize
            }
            // Skip chunk-ext (anything until CRLF).
            while pos + 1 < buffer.count,
                  !(buffer[pos] == 0x0D && buffer[pos + 1] == 0x0A) {
                pos &+= 1
            }
            // Consume CRLF after size.
            guard pos + 1 < buffer.count,
                  buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
            else { throw H1DecodeError.malformedChunkSize }
            pos &+= 2

            // ── Last-chunk (size 0) → end of body ────────────────
            if chunkSize == 0 {
                // Trailer block grammar (RFC 9112 §7.1):
                //   trailer-part = *( header-field CRLF )
                // The block is terminated by an empty line (CRLF).
                // Scan until we find that empty line, skipping over
                // any trailer header lines.
                trailerLoop: while true {
                    // Need at least 2 bytes to check for CRLF.
                    guard pos + 1 < buffer.count else {
                        throw H1DecodeError.incompleteChunkedBody
                    }
                    // Empty line (CRLF) → end of trailer block.
                    if buffer[pos] == 0x0D && buffer[pos + 1] == 0x0A {
                        pos &+= 2
                        return (body, pos)
                    }
                    // Not empty — this is a trailer header line.
                    // Skip to its terminating CRLF.
                    while pos + 1 < buffer.count,
                          !(buffer[pos] == 0x0D && buffer[pos + 1] == 0x0A) {
                        pos &+= 1
                    }
                    guard pos + 1 < buffer.count,
                          buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
                    else { throw H1DecodeError.incompleteChunkedBody }
                    pos &+= 2  // consume trailer header CRLF
                }
            }

            // ── Read chunk-data + trailing CRLF ──────────────────
            guard pos + chunkSize + 1 < buffer.count else {
                throw H1DecodeError.incompleteChunkedBody
            }
            // Pre-check total body size BEFORE appending — prevents
            // allocating a huge chunk that would immediately be rejected.
            if body.count + chunkSize > maxBodyBytes {
                throw H1DecodeError.requestTooLarge
            }
            body.append(contentsOf: buffer[pos..<(pos + chunkSize)])
            pos &+= chunkSize
            // Consume CRLF after data.
            guard buffer[pos] == 0x0D, buffer[pos + 1] == 0x0A
            else { throw H1DecodeError.malformedChunkData }
            pos &+= 2
        }

        // We exhausted the buffer without seeing the terminating 0-chunk.
        throw H1DecodeError.incompleteChunkedBody
    }

    /// Parse an ASCII hex string into an Int. Returns `nil` on invalid
    /// digits or if the value exceeds the 1 GiB per-chunk cap.
    ///
    /// Overflow-safe on all architectures (32-bit and 64-bit). The
    /// pre-check `result > (maxChunkSize - digit) / 16` catches
    /// values that would overflow or exceed the cap BEFORE the
    /// multiply, preventing Swift's trap-on-overflow.
    @inlinable
    internal static func parseHex<S: Sequence>(_ bytes: S) -> Int?
    where S.Element == UInt8 {
        let maxChunkSize = 1024 * 1024 * 1024  // 1 GiB per chunk
        var result = 0
        for b in bytes {
            let digit: Int
            switch b {
            case 0x30...0x39: digit = Int(b - 0x30)        // 0-9
            case 0x41...0x46: digit = Int(b - 0x41 + 10)   // A-F
            case 0x61...0x66: digit = Int(b - 0x61 + 10)   // a-f
            default: return nil
            }
            // Pre-check: result * 16 + digit must not exceed maxChunkSize.
            // Rearranged to avoid overflow: result <= (max - digit) / 16.
            // Safe on all architectures: max - digit is always positive
            // (max = 1 GiB, digit ≤ 15), and the division result fits Int32.
            if result > (maxChunkSize - digit) / 16 { return nil }
            result = result * 16 + digit
        }
        return result
    }

    // MARK: - SWAR-style byte helpers (kept simple for v0.1)

    /// Find `needle` in `buffer[from..<upto]`. Linear scan.
    /// SWAR-accelerated byte search via `ByteSearch.findByte`.
    /// Scans 8 bytes per iteration; ~5× faster than naive loop.
    @inlinable
    internal func findByte(_ needle: UInt8, from start: Int, upto end: Int) -> Int? {
        buffer.withUnsafeBufferPointer { ptr in
            ByteSearch.findByte(needle, in: ptr, from: start, to: end)
        }
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

    /// Case-insensitive ASCII compare against "host" (4 bytes).
    /// Short-circuits on length first — most header names differ in
    /// length, making this ~1 comparison for the common case.
    @inlinable
    internal static func isHost(_ name: ArraySlice<UInt8>) -> Bool {
        name.count == 4
            && (name[name.startIndex] | 0x20) == 0x68     // h
            && (name[name.startIndex + 1] | 0x20) == 0x6F // o
            && (name[name.startIndex + 2] | 0x20) == 0x73 // s
            && (name[name.startIndex + 3] | 0x20) == 0x74 // t
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

/// Extension-scoped carrier for the total bytes consumed by a chunked
/// body parse (headers + all chunks + terminating 0-chunk). Used by
/// decode() to consume the correct number of bytes from the [UInt8] buffer.
public struct ChunkedBytesConsumed: Hashable, Sendable {
    public let value: Int
    @inlinable public init(_ value: Int) { self.value = value }
}
