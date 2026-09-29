//===----------------------------------------------------------------------===//
//
//  H1Conn.swift
//  HTTPCodec/Proto/H1
//
//  HTTP/1.1 connection driver — actor with state machine.
//
//  Direct port of hyper's `proto::h1::Conn` state machine
//  (Reading::Init / Continue / Body / KeepAlive / Closed) adapted to
//  Swift's actor + async/await concurrency model. `decodeHead()`
//  parses only request headers; the body is pulled lazily via
//  `nextBodyChunk()`.
//
//  Runtime-agnostic: all socket reads/writes go through the injected
//  `Http1ConnectionIO` (port of hyper::rt::Read/Write). In the
//  Starlight workspace, StarlightServer supplies a `PollEventLoopIO`
//  that adapts this to a pulsar channel — the analogue of hyper's
//  tokio integration.
//
//  Thread-safety: the actor pins itself to the injected executor (via
//  `unownedExecutor`). All mutable state is actor-isolated — no
//  `@unchecked Sendable`. Cross-actor calls from the same executor
//  (the normal case for a connection driver) execute inline through
//  `isSameExclusiveExecutionContext`.
//
//  Lifetime: one `H1Conn` per TCP connection, amortised across all
//  keep-alive requests on that connection. `generation` increments
//  on every `decodeHead()` so stale body reads (from a handler that
//  escaped its `Request`) throw `BodyError.connectionAdvanced`
//  instead of corrupting the next request.
//
//  Error taxonomy (mapped from the runtime read contract:
//  `>0` data / `0` EOF / `-1` error|cancel / `-2` phase-deadline):
//
//    - `.timedOut`           — read returned `-2` (phase deadline hit)
//    - `.incompleteMessage`  — read returned `0` while a message
//                              (partial head or body) was in flight
//    - `.ioError`            — read returned `-1`
//    - parse errors          — malformed wire bytes (400-class);
//                              `.requestTooLarge` is 413-class
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTPModel

/// Errors thrown by `H1Conn` during head parsing and body framing.
///
/// All smuggling-related rejections are preserved — these are the
/// regression targets A17-A28 plus the v0.3 hardening additions
/// (bare CR/LF in header values, CL+TE conflict, conflicting CL,
/// missing/multiple Host, malformed chunk framing, header bombs,
/// non-chunked-final Transfer-Encoding, obs-fold, CTL in method /
/// request target).
public enum H1ConnError: Error, Sendable, Equatable {
    /// The request line doesn't fit `METHOD SP TARGET SP HTTP/x.y CRLF`
    /// (also covers: multiple SP separators, control chars in the
    /// method or the request target, non-token method bytes).
    case malformedRequestLine
    /// A header line doesn't fit `Name: Value CRLF` (also covers
    /// obs-fold line folding and non-token bytes in the name).
    case malformedHeader(line: Int)
    /// The HTTP version string is not `HTTP/1.0` or `HTTP/1.1`.
    case unsupportedVersion(String)
    /// The request header block exceeds `maxHeaderBytes`.
    case requestTooLarge
    /// The `Content-Length` header was present but was not a bare
    /// sequence of ASCII digits ("+5", "5.0", hex, or similar are
    /// rejected — classic CL-smuggling forms).
    case invalidContentLength
    /// Multiple `Content-Length` headers with conflicting values —
    /// potential HTTP smuggling (RFC 9112 §6.3.6).
    case conflictingContentLength
    /// Too many headers (> `maxHeaderCount`). Header-bomb defence.
    case tooManyHeaders
    /// An empty header name was encountered (RFC 9112 §5.1).
    case emptyHeaderName
    /// A `Transfer-Encoding: chunked` request body was malformed.
    case malformedChunkSize
    case malformedChunkData
    /// A header value contained a bare CR (0x0D) or LF (0x0A) that
    /// is not part of a CRLF pair (RFC 9112 §5.1), or another
    /// forbidden control byte. Header-injection / smuggling guard.
    case bareCrLfInHeader(line: Int)
    /// An HTTP/1.1 request without a `Host` header (RFC 9112 §3.2).
    case missingHost
    /// More than one `Host` header (RFC 9112 §3.2 — MUST be rejected
    /// with 400; a classic front/back-end desync vector).
    case multipleHost
    /// Both `Content-Length` and `Transfer-Encoding: chunked` were
    /// present — reject to defeat CL.TE / TE.CL smuggling.
    case conflictingFraming
    /// A `Transfer-Encoding` was present that does not end in
    /// `chunked` (we only decode chunked framing — anything else
    /// would desync the connection), `chunked` applied more than
    /// once, or `chunked` on an HTTP/1.0 request (RFC 9112 §6.1).
    case unsupportedTransferEncoding
    /// The phase deadline (header / body / drain) elapsed before the
    /// pending read was answered — runtime read returned `-2`.
    case timedOut
    /// The peer closed the connection while a head or body was only
    /// partially delivered (runtime read returned `0` mid-message).
    case incompleteMessage
    /// I/O error during read (EBADF, ECANCELED teardown, EIO, …) —
    /// runtime read returned `-1`.
    case ioError
    /// A trailer line after a chunked body was not a valid
    /// `Name: Value` header line.
    case malformedTrailer
    /// `nextBodyChunk` was called before any request head had been
    /// decoded for that generation (API misuse). Returned instead of
    /// trapping so a rogue handler cannot kill the process.
    case noActiveRequest
}

/// One parsed request head + metadata needed by the dispatcher.
public struct DecodedHead: Sendable {
    /// The parsed request. Body is `.empty` if there is no body, or
    /// `.pull(...)` set up by the caller after `decodeHead` returns.
    public let request: Request
    /// Generation counter at the time of decode — pass back to
    /// `nextBodyChunk(forGeneration:)` to detect stale body reads.
    public let generation: UInt64
    /// Keep-alive decision computed from the request's Connection
    /// header **before** hop-by-hop stripping.
    public let keepAlive: Bool
    /// Whether the request has a body (CL > 0 or chunked TE).
    public let hasBody: Bool
    /// Whether `Expect: 100-continue` was present and a 100 Continue
    /// interim response should be sent before reading the body.
    public let expects100Continue: Bool

    @inlinable
    public init(
        request: Request,
        generation: UInt64,
        keepAlive: Bool,
        hasBody: Bool,
        expects100Continue: Bool
    ) {
        self.request = request
        self.generation = generation
        self.keepAlive = keepAlive
        self.hasBody = hasBody
        self.expects100Continue = expects100Continue
    }
}

// MARK: - Token-list helper (shared with ServerTransaction)

/// Comma-separated token-list utilities for header field values
/// (`Connection`, `Transfer-Encoding`). Operates on raw bytes —
/// no allocation, no `String` round-trip.
enum TokenList {

    // Immortal token constants — array literals in Swift allocate a
    // fresh buffer on EVERY evaluation, and these appear on the
    // per-request hot path.
    static let closeToken: [UInt8] = [0x63, 0x6C, 0x6F, 0x73, 0x65]  // "close"
    static let keepAliveToken: [UInt8] = [0x6B, 0x65, 0x65, 0x70, 0x2D, 0x61, 0x6C, 0x69, 0x76, 0x65]  // "keep-alive"
    static let upgradeToken: [UInt8] = [0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65]  // "upgrade"
    static let expect100ContinueToken: [UInt8] = [0x31, 0x30, 0x30, 0x2D, 0x63, 0x6F, 0x6E, 0x74, 0x69, 0x6E, 0x75, 0x65]  // "100-continue"
    static let chunkedToken: [UInt8] = [0x63, 0x68, 0x75, 0x6E, 0x6B, 0x65, 0x64]  // "chunked"

    /// RFC 9110 tchar — valid byte in a token (methods, header names,
    /// token list elements).
    @inline(__always)
    static func isTokenByte(_ b: UInt8) -> Bool {
        if b >= 0x61 && b <= 0x7A { return true }  // a-z
        if b >= 0x41 && b <= 0x5A { return true }  // A-Z
        if b >= 0x30 && b <= 0x39 { return true }  // 0-9
        switch b {
        case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,  // ! # $ % & '
             0x2A, 0x2B, 0x2D, 0x2E,              // * + - .
             0x5E, 0x5F, 0x60, 0x7C, 0x7E:        // ^ _ ` | ~
            return true
        default:
            return false
        }
    }

    /// Iterate the elements of a comma-separated token list
    /// (RFC 9110 §5.6.1): OWS trimmed per element; empty elements
    /// (sender errors a recipient MUST ignore) are skipped.
    /// Single tokenizer for every list consumer in the codec —
    /// `Connection` token matching, Transfer-Encoding analysis.
    @inline(__always)
    static func forEachToken(
        _ list: [UInt8],
        _ body: (ArraySlice<UInt8>) -> Void
    ) {
        let n = list.count
        var i = 0
        while i < n {
            // Skip OWS and commas.
            while i < n && (list[i] == 0x20 || list[i] == 0x09 || list[i] == 0x2C) {
                i &+= 1
            }
            let start = i
            while i < n && list[i] != 0x2C { i &+= 1 }
            let end = i
            // Trim trailing OWS.
            var e = end
            while e > start && (list[e - 1] == 0x20 || list[e - 1] == 0x09) {
                e &-= 1
            }
            var s = start
            while s < e && (list[s] == 0x20 || list[s] == 0x09) {
                s &+= 1
            }
            if s < e {
                body(list[s..<e])
            }
        }
    }

    /// Case-insensitive ASCII equality of a token slice and a
    /// lowercase reference array (`| 0x20` lowers A-Z).
    @inline(__always)
    static func sliceEqualCaseInsensitive(
        _ a: ArraySlice<UInt8>, _ b: [UInt8]
    ) -> Bool {
        guard a.count == b.count else { return false }
        var i = a.startIndex
        var j = 0
        while j < b.count {
            if (a[i] | 0x20) != b[j] { return false }
            i &+= 1
            j &+= 1
        }
        return true
    }

    /// Case-insensitive ASCII equality of two byte sequences
    /// (`| 0x20` lowers A-Z; every other byte maps to itself for the
    /// purposes of this comparison).
    @inline(__always)
    static func bytesEqualCaseInsensitive(
        _ a: ArraySlice<UInt8>, _ b: UnsafeBufferPointer<UInt8>
    ) -> Bool {
        guard a.count == b.count else { return false }
        var i = a.startIndex
        var j = 0
        while j < b.count {
            if (a[i] | 0x20) != b[j] { return false }
            i &+= 1
            j &+= 1
        }
        return true
    }

    /// RFC 9112 §7.2.1: chunked must be the LAST codeword in the
    /// Transfer-Encoding list, applied exactly once. Aggregates
    /// across multiple TE headers / values, which concatenate per
    /// RFC 9110 §5.2.
    @inline(__always)
    static func analyzeTransferEncoding(
        _ valueBytes: [UInt8],
        chunkedCount: inout Int,
        lastTokenChunked: inout Bool
    ) {
        let chunked = TokenList.chunkedToken
        forEachToken(valueBytes) { token in
            var isChunked = token.count == chunked.count
            if isChunked {
                for k in 0..<chunked.count where (token[token.startIndex &+ k] | 0x20) != chunked[k] {
                    isChunked = false
                    break
                }
            }
            if isChunked { chunkedCount &+= 1 }
            lastTokenChunked = isChunked
        }
    }

    /// Check whether a comma-separated token list (mixed-case; the
    /// comparison is case-insensitive) contains `token` as a complete
    /// element. Generic over any byte Collection — arrays, parse
    /// buffer slices, borrowed header-value buffers.
    ///
    /// Unlike a substring match, `"closeness"` does NOT match
    /// `"close"` — the token must be bounded by OWS, a comma, or the
    /// end of the list.
    @inlinable
    static func contains<C: RandomAccessCollection>(
        _ list: C, token: [UInt8]
    ) -> Bool where C.Element == UInt8 {
        var i = list.startIndex
        let endIdx = list.endIndex
        while i < endIdx {
            // Skip OWS and commas.
            while i < endIdx,
                  list[i] == 0x20 || list[i] == 0x09 || list[i] == 0x2C {
                i = list.index(after: i)
            }
            let start = i
            while i < endIdx, list[i] != 0x2C {
                i = list.index(after: i)
            }
            // Trim trailing OWS.
            var e = i
            while e > start,
                  list[list.index(before: e)] == 0x20
                  || list[list.index(before: e)] == 0x09 {
                e = list.index(before: e)
            }
            var s = start
            while s < e, list[s] == 0x20 || list[s] == 0x09 {
                s = list.index(after: s)
            }
            guard list.distance(from: s, to: e) == token.count else { continue }
            var j = 0
            var idx = s
            var matched = true
            while idx < e {
                if (list[idx] | 0x20) != token[j] { matched = false; break }
                j &+= 1
                idx = list.index(after: idx)
            }
            if matched { return true }
        }
        return false
    }
}

// MARK: - H1Conn actor

/// HTTP/1.1 connection driver — actor with state machine.
///
/// One instance per TCP connection. `decodeHead()` parses request
/// headers and sets up body framing; `nextBodyChunk(forGeneration:)`
/// pulls body bytes lazily from the underlying I/O.
///
/// All mutable state is actor-isolated. The actor's executor is the
/// connection's event loop (via `unownedExecutor`), so calls from
/// `driveConnection` (which runs on the same eventLoop) execute
/// inline — zero hop overhead on the hot path.
public actor H1Conn<IO: Http1ConnectionIO> {

    // MARK: - Immutable configuration (nonisolated)

    /// Runtime-supplied I/O (port of hyper::rt::Read/Write). In
    /// StarlightServer this is a `PollEventLoopIO` over a pulsar
    /// channel; the codec itself never touches a fd or epoll.
    /// Generic (not existential) so calls monomorphise and the hot
    /// read path stays inlined.
    public nonisolated let io: IO
    /// Executor the actor pins to (a pulsar `PollEventLoop` in
    /// StarlightServer). Injected so the codec stays runtime-agnostic.
    public nonisolated let executor: UnownedSerialExecutor
    public nonisolated let maxHeaderBytes: Int
    public nonisolated let maxBodyBytes: Int
    public nonisolated let maxHeaderCount: Int
    public nonisolated let readTimeout: Duration

    /// Pin this actor to the injected executor so all method calls
    /// execute on the connection's loop thread. Combined with
    /// `isSameExclusiveExecutionContext` this gives zero-hop inline
    /// execution for the `driveConnection` → `H1Conn` calls.
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor
    }

    // MARK: - Mutable state (actor-isolated)

    /// Persistent read buffer — bytes from the runtime accumulate
    /// here; parsed headers and body chunks are consumed via
    /// `readPos` and periodically compacted away (see
    /// `maybeCompact()`).
    var buffer: [UInt8] = []
    /// Consumed position — bytes before `readPos` are no longer
    /// needed. Compacted periodically to avoid unbounded growth.
    var readPos: Int = 0
    /// Resume position for the incremental `\r\n\r\n` scan. After a
    /// failed scan only the last 3 bytes can still begin a
    /// terminator, so the next attempt starts at
    /// `max(readPos, buffer.count - 3)` — a slow-drip client costs
    /// O(total bytes), not O(n²) re-scans (Slowloris defence).
    var headerScanPos: Int = 0

    /// Connection-level state machine — mirrors hyper's `Reading`
    /// enum.
    var state: State = .readingHead

    /// Incremented on every successful `decodeHead()`. Captured by
    /// `RequestBodyStream` closures and checked in `nextBodyChunk` —
    /// detects stale body reads from handlers that escaped their
    /// `Request` past the next keep-alive cycle.
    var generation: UInt64 = 0

    /// Set by `decodeHead` when `Expect: 100-continue` is present.
    /// Cleared by the first `nextBodyChunk` call (which sends the
    /// interim 100 Continue response). NOT sent by `drainBody` —
    /// by drain time the final response has typically been written
    /// already, and an interim response after a final one is a wire
    /// violation (the runtime should close instead: see
    /// `hasStartedReadingBody()`).
    var pending100Continue: Bool = false

    /// Reusable `HeaderMap` / `Extensions` — preserve capacity across
    /// keep-alive requests (COW on the value handed to Request).
    var reusableHeaders = HeaderMap()
    var reusableExtensions = Extensions()

    /// Chunked-body sub-state (only meaningful when
    /// `state == .readingChunkedBody`).
    var chunkState: ChunkState = .readSize

    /// Bytes consumed from the body so far — used for `maxBodyBytes`
    /// enforcement on streaming chunked bodies. Counted exactly once
    /// (in the chunk readers), never re-counted by `drainBody`.
    var bodyBytesConsumed: Int = 0

    /// Trailer lines seen for the current chunked body — capped by
    /// `maxHeaderCount` (trailers are headers; same bomb defence).
    var trailerLines: Int = 0
    /// Total trailer bytes seen — capped by `maxHeaderBytes`.
    var trailerBytes: Int = 0

    /// Trailers received after the current chunked body. `nil` until
    /// the first retained trailer line arrives; populated during the
    /// `.trailers` sub-state; handed out via
    /// `trailers(forGeneration:)` once the body completes.
    var currentTrailers: HeaderMap? = nil
    /// True once the trailer section was FULLY consumed (the empty
    /// terminator line seen). Guards `trailers(forGeneration:)`:
    /// partial trailers (an error hit mid-section) must never be
    /// visible as valid data — completeness is a state-machine fact,
    /// not derived from the connection state (`.closed` after a
    /// mid-trailer error would otherwise expose a partial map).
    var trailersComplete: Bool = false

    /// Absolute deadline for the current read phase (header / body /
    /// drain). Set at each phase entry; the runtime's timer sweep
    /// fails the pending read with `-2` once it passes. Per-phase
    /// (not per-read) so a slow-drip client (Slowloris) is bounded
    /// across the WHOLE phase, not just per `read(2)`.
    var readDeadline: ContinuousClock.Instant?
    /// True once the body phase has started for the current
    /// generation (first `nextBodyChunk`). Guards the lazy one-shot
    /// assignment of the body deadline so each chunk doesn't reset
    /// it. Reset by `decodeHead`.
    var bodyReadStarted: Bool = false

    enum State: Sendable {
        case readingHead
        case readingBody(remaining: Int)
        case readingChunkedBody
        case bodyDone
        case closed
    }

    enum ChunkState: Sendable {
        case readSize
        case data(remaining: Int)
        case afterDataCrlf
        case trailers
    }

    // MARK: - Init

    public init(
        io: IO,
        executor: UnownedSerialExecutor,
        maxHeaderBytes: Int = 64 * 1024,
        maxBodyBytes: Int = 2 * 1024 * 1024,
        maxHeaderCount: Int = 100,
        readTimeout: Duration = .seconds(30)
    ) {
        precondition(
            readTimeout > .zero,
            "H1Conn: readTimeout must be > 0 (a zero timeout would fail every read)"
        )
        self.io = io
        self.executor = executor
        self.maxHeaderBytes = maxHeaderBytes
        self.maxBodyBytes = maxBodyBytes
        self.maxHeaderCount = maxHeaderCount
        self.readTimeout = readTimeout
    }

    // MARK: - Public API

    /// Parse one request head. Returns `nil` on clean EOF (client
    /// closed the connection between requests, with no partial
    /// request buffered).
    ///
    /// Loops internally: tries to parse from the buffer, reads more
    /// bytes from the socket if needed, enforces `maxHeaderBytes`
    /// against header-bomb attacks, and respects `readTimeout`
    /// (every socket read is bounded by a per-phase absolute
    /// deadline).
    ///
    /// Error mapping (server should translate to status / close):
    /// - `.timedOut`, `.incompleteMessage`, `.ioError` → close
    ///   (optionally 408 for `.timedOut` on the head phase)
    /// - `.requestTooLarge` → 413 + close
    /// - everything else (parse errors) → 400 + close
    public func decodeHead() async throws -> DecodedHead? {
        try Task.checkCancellation()

        // Reading a head on a closed connection is a caller bug or a
        // post-error retry — report clean EOF; the runtime's teardown
        // will surface the real condition on the next I/O.
        if case .closed = state { return nil }

        // Header phase: a fresh deadline per request bounds the whole
        // header parse (defends slow-drip Slowloris — a per-read
        // bound would not, since each dripped byte arrives within the
        // window). Also reset the body-phase marker for the new
        // request.
        readDeadline = ContinuousClock.now + readTimeout
        bodyReadStarted = false
        headerScanPos = readPos

        while true {
            skipLeadingCrlf()

            // ── Buffer path ────────────────────────────────────────
            // Bytes are already accumulated (a pipelined tail from a
            // previous read, or a head that spans several reads).
            // Parse directly over the buffer — rebased to the
            // unconsumed region, resuming the terminator scan from
            // `headerScanPos` (Slowloris defence: O(total), not
            // O(n²) re-scans).
            if readPos < buffer.count {
                let start = readPos
                var parsed: ParsedHead?
                do {
                    parsed = try Self.parseHead(
                        from: buffer[start...],
                        scanFrom: Swift.max(0, headerScanPos - start),
                        maxHeaderBytes: maxHeaderBytes,
                        maxHeaderCount: maxHeaderCount,
                        into: &reusableHeaders
                    )
                } catch {
                    // Any parse failure poisons the framing — never
                    // let the connection continue on a half-consumed
                    // head.
                    state = .closed
                    throw error
                }
                if let parsed {
                    let head = try applyParsed(parsed)
                    readPos = start + parsed.consumed
                    headerScanPos = readPos
                    maybeCompact()
                    return head
                }
                // Incomplete: remember how far the terminator scan
                // got (a new match can only begin in the last 3
                // bytes) and bound the accumulated unparsed bytes.
                headerScanPos = Swift.max(readPos, buffer.count - 3)
                if buffer.count - readPos > maxHeaderBytes {
                    state = .closed
                    throw H1ConnError.requestTooLarge
                }
            }

            // ── Read ───────────────────────────────────────────────
            let n = await readWithTimeout()
            if n == 0 {
                if buffer.count > readPos {
                    // EOF with a partial request buffered — that is a
                    // truncated message, not a clean idle close.
                    state = .closed
                    throw H1ConnError.incompleteMessage
                }
                // Clean EOF between requests — not an error.
                return nil
            }
            if n == -2 {
                state = .closed
                throw H1ConnError.timedOut
            }
            if n < 0 {
                state = .closed
                throw H1ConnError.ioError
            }
            try Task.checkCancellation()

            // ── View fast path ─────────────────────────────────────
            // With nothing accumulated, parse straight out of the
            // runtime's read buffer: the head is never copied at
            // all — only bytes beyond it (body / pipelined tail)
            // land in our buffer. This is the common case: a whole
            // small request arriving in a single read. The view is
            // valid until the next read, and no read happens while
            // we hold it.
            if readPos == buffer.count {
                let view = io.readView(count: n)
                // Leading CRLFs (RFC 9112 §2.2) are skipped within
                // the view.
                var off = 0
                while off + 1 < view.count,
                      view[off] == 0x0D, view[off + 1] == 0x0A {
                    off &+= 2
                }
                let src = UnsafeBufferPointer<UInt8>(
                    start: view.baseAddress! + off,
                    count: view.count - off
                )
                var parsed: ParsedHead?
                do {
                    parsed = try Self.parseHeadBytes(
                        from: src,
                        scanFrom: 0,
                        maxHeaderBytes: maxHeaderBytes,
                        maxHeaderCount: maxHeaderCount,
                        into: &reusableHeaders
                    )
                } catch {
                    state = .closed
                    throw error
                }
                if let parsed {
                    let head = try applyParsed(parsed)
                    // Recycle the (empty) buffer; copy only the tail
                    // beyond the consumed head.
                    buffer.removeAll(keepingCapacity: true)
                    readPos = 0
                    headerScanPos = 0
                    if parsed.consumed < src.count {
                        buffer.append(contentsOf: UnsafeBufferPointer<UInt8>(
                            start: src.baseAddress! + parsed.consumed,
                            count: src.count - parsed.consumed
                        ))
                    }
                    return head
                }
                if src.count > maxHeaderBytes {
                    state = .closed
                    throw H1ConnError.requestTooLarge
                }
                // Incomplete head within the view — accumulate and
                // continue on the buffer path.
                buffer.append(contentsOf: src)
                headerScanPos = Swift.max(readPos, buffer.count - 3)
                continue
            }

            // Buffer holds a partial head — accumulate the new bytes
            // next to it.
            appendReadView(count: n)
        }
    }

    /// Apply a parsed head to the connection state machine (framing,
    /// generation, request construction). Throws `requestTooLarge`
    /// for a Content-Length above `maxBodyBytes` before any state is
    /// applied.
    private func applyParsed(_ parsed: ParsedHead) throws -> DecodedHead {
        switch parsed.framing {
        case .none:
            state = .bodyDone
        case .contentLength(let cl):
            if cl > maxBodyBytes {
                state = .closed
                throw H1ConnError.requestTooLarge
            }
            state = .readingBody(remaining: cl)
            bodyBytesConsumed = 0
        case .chunked:
            state = .readingChunkedBody
            chunkState = .readSize
            bodyBytesConsumed = 0
            trailerLines = 0
            trailerBytes = 0
        }
        pending100Continue = parsed.wants100Continue

        reusableExtensions.removeAll()
        let request = Request(
            method: parsed.method,
            uri: parsed.uri,
            version: parsed.version,
            headers: reusableHeaders,
            body: .empty,  // the connection driver sets .pull(...) if hasBody
            extensions: reusableExtensions
        )
        generation &+= 1
        return DecodedHead(
            request: request,
            generation: generation,
            keepAlive: parsed.keepAlive,
            hasBody: parsed.hasBody,
            expects100Continue: parsed.wants100Continue
        )
    }

    /// Pull the next body chunk. Returns `nil` when the body is
    /// fully delivered.
    ///
    /// - Parameter gen: The generation captured by the body stream
    ///   closure. Throws `BodyError.connectionAdvanced` if the
    ///   connection has moved on to the next keep-alive request.
    public func nextBodyChunk(forGeneration gen: UInt64) async throws -> [UInt8]? {
        try Task.checkCancellation()

        if gen != generation {
            throw BodyError.connectionAdvanced
        }

        // Marks the body phase for the connection driver (see
        // `hasStartedReadingBody`). NOTE: body reads are NOT bounded
        // by an absolute phase deadline — a legitimate slow upload
        // must not be killed mid-flight. Each read is stall-bounded
        // individually (nginx `client_body_timeout` semantics); the
        // total is bounded by `maxBodyBytes`.
        if !bodyReadStarted {
            bodyReadStarted = true
        }

        // First body read on an Expect: 100-continue request sends
        // the interim response so the client proceeds with the body.
        // A partial/failed write is fatal for the connection — the
        // client would otherwise wait forever for a 100 that never
        // fully arrived.
        if pending100Continue {
            pending100Continue = false
            try send100Continue()
        }

        switch state {
        case .readingHead:
            // No head was ever decoded for this generation — API
            // misuse (the pull closure of a real request always
            // carries generation ≥ 1). Degrade to an error instead of
            // trapping: a rogue handler must not kill the process.
            throw H1ConnError.noActiveRequest
        case .bodyDone, .closed:
            return nil
        case .readingBody(var remaining):
            return try await readCLBodyChunk(remaining: &remaining)
        case .readingChunkedBody:
            return try await readChunkedBodyChunk()
        }
    }

    /// True when there is nothing left to read for the current
    /// request's body (CL fully delivered, chunked terminator seen,
    /// or the connection errored out).
    public func isBodyDone() -> Bool {
        switch state {
        case .bodyDone, .closed: return true
        default: return false
        }
    }

    /// True once `nextBodyChunk` has been called for the current
    /// request (i.e. the handler actually started consuming the
    /// body). The connection driver uses this together with
    /// `DecodedHead.expects100Continue`: if the handler never touched
    /// the body, the client may still be waiting for a `100
    /// Continue` that will never come — draining would stall until
    /// the read deadline, so the driver should close instead.
    public func hasStartedReadingBody() -> Bool {
        bodyReadStarted
    }

    /// Read and discard any remaining body bytes for the current
    /// request. Used by the connection driver after the handler
    /// returns so the buffer is left positioned at the next pipelined
    /// request. Size limits are enforced inside the chunk readers
    /// (each byte is counted exactly once — no double counting
    /// here); a violation throws and the connection must be closed.
    ///
    /// Does NOT send `100 Continue`: by drain time the final response
    /// has usually been written, and an interim response after a
    /// final one is a wire-order violation.
    public func drainBody() async throws {
        try Task.checkCancellation()

        // Drain reads are stall-bounded per read (like body reads —
        // see readCLBodyChunk): a stalled peer is failed promptly;
        // total drain time is bounded by `maxBodyBytes`.

        while !isBodyDone() {
            let chunk: [UInt8]?
            switch state {
            case .readingBody(var remaining):
                chunk = try await readCLBodyChunk(remaining: &remaining)
            case .readingChunkedBody:
                chunk = try await readChunkedBodyChunk()
            default:
                return
            }
            _ = chunk  // discarded
            try Task.checkCancellation()
        }
    }

    /// Mark the connection as closed — further reads return error.
    public func close() {
        state = .closed
    }

    /// Hand over the bytes received beyond the current request —
    /// the pre-handshake bytes of a protocol upgrade. After a 101
    /// Switching Protocols response the connection leaves HTTP
    /// framing: this drains and clears the accumulator so the tunnel
    /// receives every byte the client sent after its upgrade request
    /// (clients routinely send the first protocol frames immediately
    /// after the handshake request, before the 101 is even flushed).
    ///
    /// Must be called after the request's body framing is complete —
    /// any unconsumed request body would be discarded (a well-formed
    /// upgrade request is bodyless). The connection must not be used
    /// for further HTTP parsing afterwards.
    public func takeBufferedBytes() -> [UInt8] {
        let leftover = readPos < buffer.count ? Array(buffer[readPos...]) : []
        buffer.removeAll(keepingCapacity: true)
        readPos = 0
        headerScanPos = 0
        return leftover
    }

    // MARK: - Head parsing

    /// RFC 9112 §2.2: a server SHOULD ignore at least one empty line
    /// (CRLF) received prior to the request-line. We skip any number
    /// — each skip is 2 buffered bytes and the phase deadline bounds
    /// the drip-anomaly case. The skipped bytes are compacted away so
    /// a flood of leading CRLFs cannot pin unbounded memory.
    private func skipLeadingCrlf() {
        while buffer.count &- readPos >= 2,
              buffer[readPos] == 0x0D, buffer[readPos &+ 1] == 0x0A {
            readPos &+= 2
        }
        if headerScanPos < readPos { headerScanPos = readPos }
        maybeCompact()
    }

    /// Fully parsed request head — pure data; the actor applies it
    /// (see `applyParsed`).
    private struct ParsedHead {
        let method: Method
        let uri: Uri
        let version: Version
        let keepAlive: Bool
        let hasBody: Bool
        let wants100Continue: Bool
        let framing: Framing
        /// Bytes consumed from the source (request line + headers +
        /// terminator).
        let consumed: Int

        enum Framing: Equatable {
            case none
            case contentLength(Int)
            case chunked
        }
    }

    /// Pure head parse over borrowed, 0-based bytes. No actor state
    /// is touched: parsed headers accumulate into `headers`, framing
    /// and metadata come back in the returned `ParsedHead`. This is
    /// the single parser for both entry points — the connection's
    /// accumulator and the runtime's read-view fast path (which
    /// parses a request without ever copying its head).
    ///
    /// `scanFrom` resumes the `\r\n\r\n` scan (Slowloris defence —
    /// everything before it is known not to start a terminator).
    private nonisolated static func parseHeadBytes(
        from src: UnsafeBufferPointer<UInt8>,
        scanFrom: Int,
        maxHeaderBytes: Int,
        maxHeaderCount: Int,
        into headers: inout HeaderMap
    ) throws -> ParsedHead? {
        // 1. Locate the `\r\n\r\n` terminator (incrementally — see
        //    `headerScanPos`).
        guard let headerEnd = ByteSearch.findCRLFCRLF(
            in: src, from: scanFrom, to: src.count
        ) else {
            return nil
        }

        // Enforce the header limit on COMPLETE heads too — the
        // decode-loop check only fires while the terminator is still
        // missing, so without this an oversized head that arrived in
        // one piece would slip through. `headerEnd` is the exact head
        // size (request line + headers + terminator), independent of
        // any bytes after it.
        if headerEnd > maxHeaderBytes {
            throw H1ConnError.requestTooLarge
        }

        var pos = 0

        // ── Request line: METHOD SP TARGET SP HTTP/1.x CRLF ────────
        // Exactly one SP between fields (RFC 9112 §3: request-line =
        // method SP request-target SP HTTP-version). Lenient multi-SP
        // parsing is a front/back-end desync vector — strict peers
        // (httparse, nginx) reject it, lenient ones don't.
        guard let methodEnd = ByteSearch.findByte(0x20, in: src, from: pos, to: headerEnd),
              methodEnd > pos,
              methodEnd &+ 1 < headerEnd,
              src[methodEnd &+ 1] != 0x20
        else { throw H1ConnError.malformedRequestLine }
        // Method must be a bare token (rejects bare CR/LF smuggled
        // into the request line and log-forging control bytes).
        for i in pos..<methodEnd where !TokenList.isTokenByte(src[i]) {
            throw H1ConnError.malformedRequestLine
        }
        let method = Method(bytes: UnsafeBufferPointer(
            start: src.baseAddress! + pos,
            count: methodEnd - pos
        ))
        pos = methodEnd &+ 1

        guard let targetEnd = ByteSearch.findByte(0x20, in: src, from: pos, to: headerEnd),
              targetEnd > pos,
              targetEnd &+ 1 < headerEnd,
              src[targetEnd &+ 1] != 0x20
        else { throw H1ConnError.malformedRequestLine }
        // Request target: visible ASCII or high bytes (raw UTF-8
        // targets are tolerated like nginx; control bytes and SP
        // are not — they cannot appear in any valid request-target
        // form and enable log forging / parser desync).
        for i in pos..<targetEnd {
            let b = src[i]
            if b <= 0x20 || b == 0x7F {
                throw H1ConnError.malformedRequestLine
            }
        }
        let uri = Uri(bytes: Array(src[pos..<targetEnd]))
        pos = targetEnd &+ 1

        // Version: HTTP/1.x — starts immediately after the single SP.
        guard pos &+ 10 <= headerEnd,
              src[pos] == 0x48, src[pos &+ 1] == 0x54,
              src[pos &+ 2] == 0x54, src[pos &+ 3] == 0x50,
              src[pos &+ 4] == 0x2F,  // "HTTP/"
              src[pos &+ 5] == 0x31,  // '1'
              src[pos &+ 6] == 0x2E   // '.'
        else {
            throw H1ConnError.unsupportedVersion(
                String(decoding: src[pos..<min(pos &+ 10, headerEnd)], as: UTF8.self)
            )
        }
        let minorVersion = src[pos &+ 7]
        let version: Version
        switch minorVersion {
        case 0x30: version = .http10
        case 0x31: version = .http11
        default:
            throw H1ConnError.unsupportedVersion(
                "HTTP/1.\(Character(UnicodeScalar(minorVersion)))"
            )
        }
        pos &+= 8
        guard pos &+ 1 < headerEnd,
              src[pos] == 0x0D, src[pos &+ 1] == 0x0A
        else { throw H1ConnError.malformedRequestLine }
        pos &+= 2

        // ── Headers ───────────────────────────────────────────────
        headers.entries.removeAll(keepingCapacity: true)
        var headerIndex = 0
        var contentLength: Int? = nil
        var teHeaderSeen = false
        var teChunkedCount = 0
        var teLastTokenChunked = false
        var hostCount = 0
        var connectionClose = false
        var connectionKeepAlive = false
        var connectionTokens: [[UInt8]] = []
        var expect100Continue = false

        while pos < headerEnd &- 2 {
            if src[pos] == 0x0D && src[pos &+ 1] == 0x0A { break }

            headerIndex &+= 1
            if headerIndex > maxHeaderCount {
                throw H1ConnError.tooManyHeaders
            }

            // Header name: token bytes up to ':'. The token check
            // also rejects obs-fold continuation lines (leading
            // SP/HTAB, RFC 9112 §5.2 obsolete line folding) and
            // names with embedded whitespace — both classic
            // front/back-end desync vectors.
            let nameStart = pos
            while pos < headerEnd && src[pos] != 0x3A && src[pos] != 0x0D {
                pos &+= 1
            }
            guard pos < headerEnd, src[pos] == 0x3A else {
                throw H1ConnError.malformedHeader(line: headerIndex)
            }
            let nameBytes = src[nameStart..<pos]
            if nameBytes.isEmpty {
                throw H1ConnError.emptyHeaderName
            }
            for b in nameBytes where !TokenList.isTokenByte(b) {
                throw H1ConnError.malformedHeader(line: headerIndex)
            }
            // Zero-alloc: the name lowercases into its (usually
            // inline) storage while borrowing the parse buffer — no
            // intermediate array, no map copy.
            let name = HeaderName(lowercasingBuffer: UnsafeBufferPointer(
                start: src.baseAddress! + nameStart,
                count: pos - nameStart
            ))
            pos &+= 1  // skip ':'
            while pos < headerEnd && (src[pos] == 0x20 || src[pos] == 0x09) {
                pos &+= 1
            }
            // Value: scan until CRLF. Reject bare CR / LF and other
            // control bytes (smuggling + injection guard). HTAB is
            // the one CTL allowed inside field values.
            let valueStart = pos
            scanLoop: while pos < headerEnd &- 1 {
                let b = src[pos]
                if b == 0x0D {
                    if src[pos &+ 1] == 0x0A { break scanLoop }
                    throw H1ConnError.bareCrLfInHeader(line: headerIndex)
                }
                if b == 0x0A {
                    throw H1ConnError.bareCrLfInHeader(line: headerIndex)
                }
                if (b < 0x20 && b != 0x09) || b == 0x7F {
                    throw H1ConnError.bareCrLfInHeader(line: headerIndex)
                }
                pos &+= 1
            }
            // Trim trailing whitespace.
            var valueEnd = pos
            while valueEnd > valueStart {
                let prev = src[valueEnd &- 1]
                if prev == 0x20 || prev == 0x09 { valueEnd &-= 1 } else { break }
            }
            // Zero-alloc: the value copies straight from the parse
            // buffer into its (usually inline) storage.
            let value = HeaderValue(borrowingBuffer: UnsafeBufferPointer(
                start: src.baseAddress! + valueStart,
                count: valueEnd - valueStart
            ))
            headers.append(name, value)
            // Framing checks read the value as a slice of the source
            // — the common (non-framing) header path copies nothing.
            let valueSlice = src[valueStart..<valueEnd]

            // Track framing-relevant headers inline.
            if Self.isContentLength(nameBytes) {
                guard let n = Self.parseAsciiDigits(valueSlice), n >= 0 else {
                    throw H1ConnError.invalidContentLength
                }
                if let existing = contentLength, existing != n {
                    throw H1ConnError.conflictingContentLength
                }
                contentLength = n
            } else if Self.isTransferEncoding(nameBytes) {
                // RFC 9112 §7.2.1: chunked must be applied exactly
                // once and must be the final coding. Aggregate across
                // multiple TE headers (they concatenate, RFC 9110
                // §5.2 list form). Rare header — materialise it.
                teHeaderSeen = true
                TokenList.analyzeTransferEncoding(
                    Array(valueSlice),
                    chunkedCount: &teChunkedCount,
                    lastTokenChunked: &teLastTokenChunked
                )
            } else if Self.isHost(nameBytes) {
                hostCount &+= 1
            } else if Self.isConnection(nameBytes) {
                // Token matching is case-insensitive — no lowering
                // copy needed. Rare header — materialise once for
                // the connection-listed strip below.
                if TokenList.contains(valueSlice, token: TokenList.closeToken) {
                    connectionClose = true
                }
                if TokenList.contains(valueSlice, token: TokenList.keepAliveToken) {
                    connectionKeepAlive = true
                }
                connectionTokens.append(Array(valueSlice))
            } else if Self.isExpect(nameBytes) {
                // "100-continue" — inline case-insensitive compare
                // over the slice, no copies.
                let token = TokenList.expect100ContinueToken
                if valueSlice.count == token.count {
                    var match = true
                    for i in 0..<token.count where (src[valueStart &+ i] | 0x20) != token[i] {
                        match = false
                        break
                    }
                    if match { expect100Continue = true }
                }
            }

            // Consume CRLF.
            guard pos &+ 1 < headerEnd,
                  src[pos] == 0x0D, src[pos &+ 1] == 0x0A
            else { throw H1ConnError.malformedHeader(line: headerIndex) }
            pos &+= 2
        }

        // RFC 9112 §3.2: 400 for a missing Host (1.1) and for more
        // than one Host (any version — duplicate Host is a prime
        // proxy-desync vector).
        if hostCount > 1 {
            throw H1ConnError.multipleHost
        }
        if version == .http11 && hostCount == 0 {
            throw H1ConnError.missingHost
        }

        // Transfer-Encoding: we only decode chunked framing. Any TE
        // that doesn't end in exactly one `chunked` codeword would
        // leave the body framing unknown — treating it as "no body"
        // desyncs the connection (TE.TE smuggling), so reject.
        if teHeaderSeen {
            if teChunkedCount == 0 || !teLastTokenChunked || teChunkedCount > 1 {
                throw H1ConnError.unsupportedTransferEncoding
            }
            if version == .http10 {
                // RFC 9112 §6.1: a server MUST NOT send chunked to a
                // 1.0 client; symmetrically reject it on requests.
                throw H1ConnError.unsupportedTransferEncoding
            }
        }

        // CL + TE conflict — reject to defeat CL.TE / TE.CL smuggling.
        if teHeaderSeen && contentLength != nil {
            throw H1ConnError.conflictingFraming
        }

        // ── Compute keep-alive BEFORE stripping hop-by-hop ─────────
        let keepAlive: Bool
        if connectionClose {
            keepAlive = false
        } else if connectionKeepAlive {
            keepAlive = true
        } else {
            // Default by version: HTTP/1.1 → keep-alive, HTTP/1.0 → close.
            keepAlive = (version == .http11)
        }

        // Strip hop-by-hop headers — handlers must not see them.
        // `upgrade` is deliberately KEPT: an upgrade handshake
        // (WebSocket) needs the handler to see it (hyper keeps it
        // too). RFC 9110 §7.6.1: headers NAMED in the Connection
        // header are also hop-by-hop for this connection — strip them
        // as well; `upgrade`/`close`/`keep-alive` tokens are exempt
        // (the first is the handshake marker, the others are tokens,
        // not header names).
        headers.entries.removeAll { (n, _) in
            switch n {
            case .connection, .keepAlive, .te, .trailer, .proxyConnection:
                return true
            default:
                return false
            }
        }
        if !connectionTokens.isEmpty {
            for value in connectionTokens {
                TokenList.forEachToken(value) { token in
                    if TokenList.sliceEqualCaseInsensitive(token, TokenList.closeToken)
                        || TokenList.sliceEqualCaseInsensitive(token, TokenList.keepAliveToken)
                        || TokenList.sliceEqualCaseInsensitive(token, TokenList.upgradeToken) {
                        return
                    }
                    // Case-insensitive compare against the (already
                    // lowercased) stored names — no lowering copy.
                    headers.entries.removeAll { (n, _) in
                        n.withUnsafeBytes { nb in
                            TokenList.bytesEqualCaseInsensitive(token, nb)
                        }
                    }
                }
            }
        }

        // ── Determine body framing ────────────────────────────────
        let hasBody: Bool
        let framing: ParsedHead.Framing
        // HEAD requests never carry a body, even with Content-Length.
        if method == .HEAD {
            hasBody = false
            framing = .none
        } else if teHeaderSeen {
            hasBody = true
            framing = .chunked
        } else if let cl = contentLength, cl > 0 {
            hasBody = true
            framing = .contentLength(cl)
        } else {
            // No CL, no TE → no body for requests (RFC 9112 §6.3).
            hasBody = false
            framing = .none
        }

        return ParsedHead(
            method: method,
            uri: uri,
            version: version,
            keepAlive: keepAlive,
            hasBody: hasBody,
            wants100Continue: hasBody && expect100Continue,
            framing: framing,
            consumed: headerEnd
        )
    }

    /// Borrowed parse over a slice of the connection accumulator.
    /// The slice's buffer keeps SLICE indices — rebased to 0 before
    /// entering the single core parser.
    private nonisolated static func parseHead(
        from slice: ArraySlice<UInt8>,
        scanFrom: Int,
        maxHeaderBytes: Int,
        maxHeaderCount: Int,
        into headers: inout HeaderMap
    ) throws -> ParsedHead? {
        try slice.withUnsafeBufferPointer { raw in
            let src = UnsafeBufferPointer<UInt8>(
                start: raw.baseAddress, count: raw.count
            )
            return try parseHeadBytes(
                from: src,
                scanFrom: scanFrom,
                maxHeaderBytes: maxHeaderBytes,
                maxHeaderCount: maxHeaderCount,
                into: &headers
            )
        }
    }

    // MARK: - Body: Content-Length bounded

    /// Pull one chunk from a CL-bounded body.
    private func readCLBodyChunk(remaining: inout Int) async throws -> [UInt8]? {
        if remaining == 0 {
            state = .bodyDone
            return nil
        }
        let available = buffer.count &- readPos
        if available == 0 {
            // Per-read stall bound: every individual read must make
            // progress within `readTimeout` (slow-but-steady uploads
            // are legit; only a stalled peer is failed).
            readDeadline = ContinuousClock.now + readTimeout
            let n = await readWithTimeout()
            if n == 0 {
                // Unexpected EOF — client closed before CL bytes arrived.
                state = .closed
                throw H1ConnError.incompleteMessage
            }
            if n == -2 {
                state = .closed
                throw H1ConnError.timedOut
            }
            if n < 0 {
                state = .closed
                throw H1ConnError.ioError
            }
            appendReadView(count: n)
            try Task.checkCancellation()
        }
        let take = Swift.min(remaining, buffer.count &- readPos)
        let chunk = Array(buffer[readPos..<(readPos &+ take)])
        readPos &+= take
        remaining &-= take
        if remaining == 0 {
            state = .bodyDone
            maybeCompact()
        } else {
            state = .readingBody(remaining: remaining)
            maybeCompact()
        }
        return chunk
    }

    // MARK: - Body: chunked Transfer-Encoding

    /// Pull one chunk from a chunked body. Drives the sub-state
    /// machine (`readSize` → `data` → `afterDataCrlf` → `readSize`,
    /// or `readSize` with size 0 → `trailers` → `bodyDone`).
    private func readChunkedBodyChunk() async throws -> [UInt8]? {
        while true {
            switch chunkState {
            case .readSize:
                // Parse "<hex>[;ext]\r\n"
                guard let (size, newPos) = try parseChunkSize() else {
                    // Need more data.
                    try await ensureBytesAvailable()
                    continue
                }
                readPos = newPos
                if size == 0 {
                    chunkState = .trailers
                    trailerLines = 0
                    trailerBytes = 0
                    continue
                }
                // Enforce maxBodyBytes on running total.
                if bodyBytesConsumed &+ size > maxBodyBytes {
                    state = .closed
                    throw H1ConnError.requestTooLarge
                }
                chunkState = .data(remaining: size)

            case .data(let remaining):
                if remaining == 0 {
                    chunkState = .afterDataCrlf
                    continue
                }
                let available = buffer.count &- readPos
                if available == 0 {
                    try await ensureBytesAvailable()
                    continue
                }
                let take = Swift.min(remaining, available)
                let chunk = Array(buffer[readPos..<(readPos &+ take)])
                readPos &+= take
                bodyBytesConsumed &+= take
                if take == remaining {
                    chunkState = .afterDataCrlf
                } else {
                    chunkState = .data(remaining: remaining &- take)
                }
                // Compact periodically: without this, a multi-MiB
                // chunked body keeps the whole consumed prefix in the
                // buffer (readPos advances but the storage never
                // shrinks until bodyDone).
                maybeCompact()
                return chunk

            case .afterDataCrlf:
                // Need 2 bytes: \r\n after chunk data.
                if buffer.count &- readPos < 2 {
                    try await ensureBytesAvailable()
                    continue
                }
                guard buffer[readPos] == 0x0D, buffer[readPos &+ 1] == 0x0A
                else {
                    state = .closed
                    throw H1ConnError.malformedChunkData
                }
                readPos &+= 2
                chunkState = .readSize

            case .trailers:
                // Scan trailer lines until the empty line. Trailers
                // are discarded for v0.1, but they are still headers
                // — bounded per-line and in total by maxHeaderBytes
                // and in count by maxHeaderCount (bomb defence;
                // without this a client can grow the buffer without
                // limit with a never-ending trailer line). The empty
                // terminator line is not counted toward the limits.
                guard let scan = try scanTrailerLine() else {
                    try await ensureBytesAvailable()
                    continue
                }
                if scan.isEmpty {
                    // End of chunked body — the trailer section is
                    // now complete and may be handed out.
                    readPos = scan.newPos
                    state = .bodyDone
                    chunkState = .readSize  // reset for next request
                    trailersComplete = true
                    maybeCompact()
                    return nil
                }
                // Otherwise it was a trailer header — parse it into
                // `currentTrailers` (available to the handler via
                // `trailers(forGeneration:)` once the body ends),
                // then account for it against the bomb-defence caps.
                let lineStart = readPos
                let lineEnd = readPos + scan.length
                readPos = scan.newPos
                try parseTrailerLine(start: lineStart, end: lineEnd)
                trailerLines &+= 1
                if trailerLines > maxHeaderCount {
                    state = .closed
                    throw H1ConnError.tooManyHeaders
                }
                trailerBytes &+= scan.length
                if trailerBytes > maxHeaderBytes {
                    state = .closed
                    throw H1ConnError.requestTooLarge
                }
            }
        }
    }

    /// Try to parse "<hex>[;ext]\r\n" from the current buffer
    /// position. Returns `(size, newPositionAfterCrlf)` or `nil`
    /// if more bytes are needed. Throws on malformed size.
    ///
    /// The chunk-size line (including any chunk-ext) is capped at
    /// `maxHeaderBytes` and the hex run at 16 digits — without the
    /// caps a client drips an endless "extension" and grows the
    /// buffer without bound (memory-exhaustion DoS).
    private func parseChunkSize() throws -> (size: Int, newPos: Int)? {
        var pos = readPos
        let n = buffer.count
        let lineLimit = readPos &+ maxHeaderBytes

        // Scan hex digits until CR or ';' (chunk-ext).
        let sizeStart = pos
        while pos < n && buffer[pos] != 0x0D && buffer[pos] != 0x3B {
            if pos &- sizeStart >= 16 {
                // > 16 hex digits can only be leading-zero padding —
                // httparse-compatible limit.
                state = .closed
                throw H1ConnError.malformedChunkSize
            }
            if pos > lineLimit {
                state = .closed
                throw H1ConnError.requestTooLarge
            }
            pos &+= 1
        }
        guard pos < n else { return nil }  // need more

        let sizeBytes = buffer[sizeStart..<pos]
        guard !sizeBytes.isEmpty,
              let chunkSize = Self.parseHex(sizeBytes)
        else {
            state = .closed
            throw H1ConnError.malformedChunkSize
        }

        // Skip optional chunk-ext (anything until CRLF), bounded by
        // the same line limit.
        while pos &+ 1 < n,
              !(buffer[pos] == 0x0D && buffer[pos &+ 1] == 0x0A) {
            if pos > lineLimit {
                state = .closed
                throw H1ConnError.requestTooLarge
            }
            pos &+= 1
        }
        guard pos &+ 1 < n,
              buffer[pos] == 0x0D, buffer[pos &+ 1] == 0x0A
        else {
            return nil  // need more
        }
        pos &+= 2  // consume CRLF
        return (chunkSize, pos)
    }

    /// Look at the current position. Returns
    /// `(isEmptyLine, lineByteLength, newPos)` where `isEmptyLine`
    /// is true if the line is empty (just CRLF, marking end of
    /// trailers) or false if it's a trailer header (skip past its
    /// CRLF). Returns nil if more bytes are needed.
    ///
    /// Defensive bounds (both throw, tearing down the connection):
    /// - a single trailer line longer than `maxHeaderBytes` (an
    ///   unterminated line would otherwise grow the buffer forever);
    /// - a bare CR or LF inside the line (same strictness as header
    ///   values — a strict/lenient mismatch here is a desync vector
    ///   against front-end proxies that do parse trailers).
    private func scanTrailerLine() throws -> (isEmpty: Bool, length: Int, newPos: Int)? {
        let n = buffer.count
        guard readPos &+ 1 < n else { return nil }
        // Empty line?
        if buffer[readPos] == 0x0D && buffer[readPos &+ 1] == 0x0A {
            return (true, 0, readPos &+ 2)
        }
        // Trailer header — scan to its terminating CRLF.
        var pos = readPos
        while pos &+ 1 < n {
            if buffer[pos] == 0x0D && buffer[pos &+ 1] == 0x0A {
                return (false, pos &- readPos, pos &+ 2)
            }
            if buffer[pos] == 0x0D || buffer[pos] == 0x0A {
                // Bare CR or LF not part of a CRLF pair.
                state = .closed
                throw H1ConnError.malformedChunkData
            }
            if pos &- readPos > maxHeaderBytes {
                // Unterminated line longer than the header cap — the
                // buffer would grow without bound if we kept reading.
                state = .closed
                throw H1ConnError.requestTooLarge
            }
            pos &+= 1
        }
        // The final byte before `n` may legally start a CRLF that
        // needs one more byte — but only if it isn't already known
        // to be a bare CR mid-line (checked above) and the line is
        // still within its cap.
        if pos < n, buffer[pos] == 0x0D, pos &- readPos > maxHeaderBytes {
            state = .closed
            throw H1ConnError.requestTooLarge
        }
        return nil  // need more
    }

    // MARK: - Trailers

    /// Trailers received after the current chunked body.
    ///
    /// Returns `nil` while the body (including its trailer section)
    /// is still being consumed, if the section was interrupted by an
    /// error (partial trailers are never visible as valid data), for
    /// Content-Length bodies (trailers are not defined there), when
    /// no trailer field was retained (empty or forbidden-only
    /// section — dropped names per RFC 9110 §6.5.1), and once the
    /// connection has moved on to a later request (stale
    /// generation).
    public func trailers(forGeneration gen: UInt64) -> HeaderMap? {
        guard gen == generation, trailersComplete else { return nil }
        return currentTrailers
    }

    /// Parse one received trailer line (`buffer[start..<end]`, the
    /// CRLF already excluded) into `currentTrailers`.
    ///
    /// Syntax is validated exactly like request headers (token name,
    /// CTL-free value — `scanTrailerLine` already rejected bare
    /// CR/LF). Framing / hop-by-hop names (RFC 9110 §6.5.1: a
    /// trailer MUST NOT include `Content-Length`, `Transfer-Encoding`,
    /// `Host`, …) are silently DROPPED, keeping the rest — hyper
    /// parity.
    private func parseTrailerLine(start: Int, end: Int) throws {
        var pos = start
        // Name: token bytes up to ':'.
        while pos < end && buffer[pos] != 0x3A {
            pos &+= 1
        }
        guard pos < end else {
            state = .closed
            throw H1ConnError.malformedTrailer
        }
        let nameBytes = buffer[start..<pos]
        guard !nameBytes.isEmpty else {
            state = .closed
            throw H1ConnError.malformedTrailer
        }
        for b in nameBytes where !TokenList.isTokenByte(b) {
            state = .closed
            throw H1ConnError.malformedTrailer
        }
        let lowered = nameBytes.map {
            (0x41...0x5A).contains($0) ? $0 &+ 0x20 : $0
        }
        // RFC 9110 §6.5.1 — framing / hop-by-hop fields are invalid
        // as trailers; drop the line, keep the rest.
        switch HeaderName(lowercasedBytes: lowered) {
        case .contentLength, .transferEncoding, .host, .connection,
             .keepAlive, .te, .trailer, .upgrade, .proxyConnection:
            return
        default:
            break
        }
        pos &+= 1  // skip ':'
        while pos < end && (buffer[pos] == 0x20 || buffer[pos] == 0x09) {
            pos &+= 1
        }
        var valueEnd = end
        while valueEnd > pos {
            let prev = buffer[valueEnd &- 1]
            if prev == 0x20 || prev == 0x09 { valueEnd &-= 1 } else { break }
        }
        let valueBytes = Array(buffer[pos..<valueEnd])
        if currentTrailers == nil { currentTrailers = HeaderMap() }
        currentTrailers?.append(
            HeaderName(lowercasedBytes: lowered),
            HeaderValue(bytes: valueBytes)
        )
    }

    // MARK: - Buffer management

    /// Read more bytes from the socket, bounded by the current phase
    /// deadline (`readDeadline`). Returns `n > 0` bytes, `0` EOF,
    /// `-1` I/O error / cancel, `-2` phase-deadline elapsed
    /// (timeout) — the raw runtime contract; callers map to
    /// `H1ConnError` cases.
    @usableFromInline
    internal func readWithTimeout() async -> Int {
        // Pass the current phase's absolute deadline straight through.
        // The runtime's timer sweep enforces it while this read is
        // suspended; no per-read `now()` check here — that would cost
        // a clock read per request for a condition (phase already
        // expired while the loop was spinning) that the sweep already
        // covers (the read is pending between dripped bytes, so a
        // sweep tick lands during the pending window and fails it on
        // the deadline).
        await io.read(deadline: readDeadline)
    }

    /// Read more bytes, append to buffer, throw on EOF/error/timeout.
    /// Used by the chunked body paths when the buffer is empty.
    private func ensureBytesAvailable() async throws {
        try Task.checkCancellation()
        // Per-read stall bound (see readCLBodyChunk).
        readDeadline = ContinuousClock.now + readTimeout
        let n = await readWithTimeout()
        if n == 0 {
            state = .closed
            throw H1ConnError.incompleteMessage
        }
        if n == -2 {
            state = .closed
            throw H1ConnError.timedOut
        }
        if n < 0 {
            state = .closed
            throw H1ConnError.ioError
        }
        appendReadView(count: n)
        try Task.checkCancellation()
    }

    /// Copy bytes from the runtime's per-channel read buffer into
    /// our `[UInt8]` accumulator. One memcpy (~10 ns for 8 KB).
    private func appendReadView(count: Int) {
        let view = io.readView(count: count)
        // view is only valid until the next read on the runtime's I/O
        // handle — copy it out immediately, as every read path does.
        buffer.append(contentsOf: view)
    }

    /// Periodically compact the buffer to prevent unbounded growth
    /// from the readPos pointer. Strategy: only compact when readPos
    /// is large (>= 1 MiB or buffer is large and readPos > 80%) so
    /// the typical small-request path pays zero O(n) cost. Called
    /// from head parsing, both body-chunk readers, and the trailer
    /// terminator — mid-body compaction is what keeps a multi-MiB
    /// streaming body from pinning its whole consumed prefix.
    private func maybeCompact() {
        let threshold = 1024 * 1024  // 1 MiB
        if readPos > threshold {
            buffer.removeFirst(readPos)
            readPos = 0
            headerScanPos = 0
        } else if buffer.count > 64 * 1024 && readPos > (buffer.count * 4 / 5) {
            buffer.removeFirst(readPos)
            readPos = 0
            headerScanPos = 0
        }
    }

    /// Send the interim `100 Continue` response directly on the
    /// socket. Done at most once per request (guarded by
    /// `pending100Continue`). A partial or failed write is fatal —
    /// the client would hang waiting for the rest — so it throws and
    /// the connection is torn down.
    private func send100Continue() throws {
        let bytes: [UInt8] = [
            0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x20,  // "HTTP/1.1 "
            0x31, 0x30, 0x30, 0x20,                                  // "100 "
            0x43, 0x6F, 0x6E, 0x74, 0x69, 0x6E, 0x75, 0x65,         // "Continue"
            0x0D, 0x0A, 0x0D, 0x0A                                   // CRLF CRLF
        ]
        let written = io.writeRaw(bytes)
        if written != bytes.count {
            state = .closed
            throw H1ConnError.ioError
        }
    }

    // MARK: - Byte search helpers

    // MARK: - Static header-name recognisers (case-insensitive)

    @inline(__always)
    private static func isContentLength(_ name: Slice<UnsafeBufferPointer<UInt8>>) -> Bool {
        // "content-length" (14 bytes)
        let expected: [UInt8] = [
            0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D,
            0x6C, 0x65, 0x6E, 0x67, 0x74, 0x68
        ]
        return matchName(name, expected: expected)
    }

    @inline(__always)
    private static func isTransferEncoding(_ name: Slice<UnsafeBufferPointer<UInt8>>) -> Bool {
        // "transfer-encoding" (17 bytes)
        let expected: [UInt8] = [
            0x74, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72, 0x2D,
            0x65, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67
        ]
        return matchName(name, expected: expected)
    }

    @inline(__always)
    private static func isHost(_ name: Slice<UnsafeBufferPointer<UInt8>>) -> Bool {
        // "host" (4 bytes) — short-circuit on length.
        guard name.count == 4 else { return false }
        let s = name.startIndex
        return (name[s] | 0x20) == 0x68      // h
            && (name[s &+ 1] | 0x20) == 0x6F // o
            && (name[s &+ 2] | 0x20) == 0x73 // s
            && (name[s &+ 3] | 0x20) == 0x74 // t
    }

    @inline(__always)
    private static func isConnection(_ name: Slice<UnsafeBufferPointer<UInt8>>) -> Bool {
        // "connection" (10 bytes)
        let expected: [UInt8] = [
            0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E
        ]
        return matchName(name, expected: expected)
    }

    @inline(__always)
    private static func isExpect(_ name: Slice<UnsafeBufferPointer<UInt8>>) -> Bool {
        // "expect" (6 bytes)
        let expected: [UInt8] = [0x65, 0x78, 0x70, 0x65, 0x63, 0x74]
        return matchName(name, expected: expected)
    }

    @inline(__always)
    private static func matchName(_ name: Slice<UnsafeBufferPointer<UInt8>>, expected: [UInt8]) -> Bool {
        guard name.count == expected.count else { return false }
        var i = 0
        for b in name {
            let lower = (0x41...0x5A).contains(b) ? b &+ 0x20 : b
            if lower != expected[i] { return false }
            i &+= 1
        }
        return true
    }

    /// Parse a bare ASCII digit sequence into an `Int` — used for
    /// `Content-Length`. Strictly digits only: no sign, no spaces, no
    /// list form ("+5", " 5", "5, 5" are all rejected — classic
    /// CL-smuggling shapes that lenient integer parsers accept).
    /// Returns `nil` on any non-digit byte or on `Int` overflow.
    /// Generic over any byte Sequence — reads parse-buffer slices
    /// without materialising.
    @inline(__always)
    private static func parseAsciiDigits<S: Sequence>(_ bytes: S) -> Int?
    where S.Element == UInt8 {
        var n = 0
        var count = 0
        for b in bytes {
            guard b >= 0x30 && b <= 0x39 else { return nil }
            count &+= 1
            let digit = Int(b &- 0x30)
            if n > (Int.max &- digit) / 10 { return nil }
            n = n &* 10 &+ digit
        }
        guard count > 0 else { return nil }
        return n
    }

    /// Parse ASCII hex into Int. Returns `nil` on invalid digits or
    /// if the value exceeds 1 GiB per-chunk cap. Overflow-safe on
    /// all architectures.
    @inline(__always)
    private static func parseHex<S: Sequence>(_ bytes: S) -> Int?
    where S.Element == UInt8 {
        let maxChunkSize = 1024 * 1024 * 1024
        var result = 0
        for b in bytes {
            let digit: Int
            switch b {
            case 0x30...0x39: digit = Int(b - 0x30)
            case 0x41...0x46: digit = Int(b - 0x41 + 10)
            case 0x61...0x66: digit = Int(b - 0x61 + 10)
            default: return nil
            }
            if result > (maxChunkSize - digit) / 16 { return nil }
            result = result * 16 + digit
        }
        return result
    }
}

// MARK: - Trailer access for handlers

/// Source of parsed chunked-body trailers. `H1Conn` conforms; the
/// connection driver inserts the bound accessor below into
/// `request.extensions` so handlers can retrieve trailers after
/// fully consuming the body.
public protocol H1TrailersSource: Sendable {
    /// Trailers for the request decoded with `gen`. `nil` until the
    /// body completes, for non-chunked bodies, or for stale
    /// generations.
    func trailers(forGeneration gen: UInt64) async -> HeaderMap?
}

extension H1Conn: H1TrailersSource {}

/// Handler-facing trailer accessor bound to one request generation.
/// Inserted into `Request.extensions` by the connection driver:
///
/// ```swift
/// if let trailers = req.extensions.get(RequestTrailers.self) {
///     let fields = await trailers.get()  // HeaderMap? — after body end
/// }
/// ```
///
/// Semantics mirror `H1Conn.trailers(forGeneration:)`: available
/// only after the chunked body (including its trailer section) has
/// been fully consumed — reading the body to completion via the
/// `.pull` closure and then calling `get()` is the intended flow.
public struct RequestTrailers: Sendable {
    public let source: H1TrailersSource
    public let generation: UInt64

    @inlinable
    public init(source: H1TrailersSource, generation: UInt64) {
        self.source = source
        self.generation = generation
    }

    /// The parsed trailer fields, or `nil` if the body has not fully
    /// arrived yet / is not chunked / the connection moved on.
    public func get() async -> HeaderMap? {
        await source.trailers(forGeneration: generation)
    }
}
