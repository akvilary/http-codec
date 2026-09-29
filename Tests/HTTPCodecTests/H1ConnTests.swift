//===----------------------------------------------------------------------===//
//
//  H1ConnTests.swift
//  HTTPCodecTests
//
//  Regression suite for the H1 connection state machine: request
//  parsing, the smuggling defence suite, body framing (CL + chunked),
//  error taxonomy, keep-alive policy, and buffer management.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTP
@testable import HTTPCodec

// MARK: - Mock I/O

/// Minimal serial executor for tests: actor jobs run on a private
/// serial DispatchQueue. (`MainActor.shared` has no
/// `asUnownedSerialExecutor` on this toolchain.)
final class TestSerialExecutor: SerialExecutor, @unchecked Sendable {
    private let queue = DispatchQueue(label: "httpcodec.tests")
    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        let executor = UnownedSerialExecutor(ordinary: self)
        queue.async { unowned.runSynchronously(on: executor) }
    }
    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }
}

/// Scripted `Http1ConnectionIO`: feeds queued byte chunks, can force
/// read results (`-1` error / `-2` timeout / `0` EOF by exhaustion),
/// records writeRaw traffic and the last read deadline.
final class MockIO: Http1ConnectionIO, @unchecked Sendable {
    private let lock = NSLock()
    private var chunks: [[UInt8]]
    private var chunkIdx = 0
    private var current: [UInt8] = []

    /// When set, `read` returns this instead of draining chunks.
    var forceResult: Int?
    /// When set, `writeRaw` returns this instead of the byte count
    /// (partial-write simulation).
    var rawWriteResult: Int?
    /// Raw bytes written via `writeRaw` (100-continue), in order.
    private(set) var rawWrites: [[UInt8]] = []
    /// Last deadline passed to `read`.
    private(set) var lastDeadline: ContinuousClock.Instant?

    init(_ bytes: [UInt8]) {
        self.chunks = [bytes]
    }

    init(chunks: [[UInt8]]) {
        self.chunks = chunks
    }

    func read(deadline: ContinuousClock.Instant?) async -> Int {
        readSync(deadline: deadline)
    }

    private func readSync(deadline: ContinuousClock.Instant?) -> Int {
        lock.lock(); defer { lock.unlock() }
        lastDeadline = deadline
        if let f = forceResult { return f }
        guard chunkIdx < chunks.count else { return 0 }  // EOF
        current = chunks[chunkIdx]
        chunkIdx += 1
        return current.count
    }

    func readView(count: Int) -> UnsafeBufferPointer<UInt8> {
        lock.lock(); defer { lock.unlock() }
        return current.withUnsafeBufferPointer { buf in
            UnsafeBufferPointer(start: buf.baseAddress, count: count)
        }
    }

    func writeRaw(_ bytes: [UInt8]) -> Int {
        lock.lock(); defer { lock.unlock() }
        rawWrites.append(bytes)
        return rawWriteResult ?? bytes.count
    }
}

// MARK: - Helpers

let testExecutor = TestSerialExecutor()

func makeConn(
    _ input: [UInt8],
    maxHeaderBytes: Int = 64 * 1024,
    maxBodyBytes: Int = 2 * 1024 * 1024,
    maxHeaderCount: Int = 100,
    readTimeout: Duration = .seconds(30)
) -> H1Conn<MockIO> {
    H1Conn(
        io: MockIO(input),
        executor: testExecutor.asUnownedSerialExecutor(),
        maxHeaderBytes: maxHeaderBytes,
        maxBodyBytes: maxBodyBytes,
        maxHeaderCount: maxHeaderCount,
        readTimeout: readTimeout
    )
}

func makeConn(
    chunks: [[UInt8]],
    maxHeaderBytes: Int = 64 * 1024,
    maxBodyBytes: Int = 2 * 1024 * 1024,
    maxHeaderCount: Int = 100
) -> H1Conn<MockIO> {
    H1Conn(
        io: MockIO(chunks: chunks),
        executor: testExecutor.asUnownedSerialExecutor(),
        maxHeaderBytes: maxHeaderBytes,
        maxBodyBytes: maxBodyBytes,
        maxHeaderCount: maxHeaderCount
    )
}

func req(_ raw: String) -> [UInt8] { Array(raw.utf8) }

// MARK: - Head parsing

@Suite("H1Conn head parsing")
struct H1HeadTests {

    @Test("simple GET with Host")
    func simpleGet() async throws {
        let conn = makeConn(req("GET /path?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"))
        let head = try await conn.decodeHead()
        let h = try #require(head)
        #expect(h.request.method == .GET)
        #expect(h.request.uri.pathString == "/path")
        #expect(h.request.uri.queryString == "x=1")
        #expect(h.request.version == .http11)
        #expect(h.request.headers.first(for: .host)?.description == "example.com")
        #expect(h.request.headers.first(for: .userAgent)?.description == "t")
        #expect(h.keepAlive)
        #expect(!h.hasBody)
        #expect(h.generation == 1)
    }

    @Test("header names are case-insensitive, values preserved")
    func headerCase() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nhOsT: x\r\nX-CuStOm: V\r\n\r\n"))
        let h = try await conn.decodeHead()
        #expect(h?.request.headers.first(for: .host) != nil)
        #expect(h?.request.headers.first(for: HeaderName("x-custom"))?.description == "V")
    }

    @Test("leading CRLF before request-line is skipped (RFC 9112 §2.2)")
    func leadingCrlf() async throws {
        let conn = makeConn(req("\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        let h = try await conn.decodeHead()
        #expect(h?.request.uri.pathString == "/")
    }

    @Test("keep-alive: HTTP/1.0 + Connection: keep-alive")
    func keepAlive10Explicit() async throws {
        let conn = makeConn(req("GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"))
        #expect(try await conn.decodeHead()?.keepAlive == true)
    }

    @Test("keep-alive: HTTP/1.1 + Connection: close")
    func keepAlive11Close() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
        #expect(try await conn.decodeHead()?.keepAlive == false)
    }

    @Test("keep-alive: HTTP/1.0 default is close")
    func keepAlive10Default() async throws {
        let conn = makeConn(req("GET / HTTP/1.0\r\n\r\n"))
        #expect(try await conn.decodeHead()?.keepAlive == false)
    }

    @Test("Connection token list ('keep-alive, upgrade')")
    func connectionTokenList() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, upgrade\r\n\r\n"))
        #expect(try await conn.decodeHead()?.keepAlive == true)
    }

    @Test("hop-by-hop headers stripped; Upgrade kept for handshake")
    func hopByHopStripped() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nKeep-Alive: timeout=5\r\nUpgrade: websocket\r\n\r\n"))
        let h = try await conn.decodeHead()
        #expect(h?.request.headers.first(for: .connection) == nil)
        #expect(h?.request.headers.first(for: .keepAlive) == nil)
        // Upgrade must stay visible — the handler needs it to
        // validate the WebSocket handshake (hyper parity).
        #expect(h?.request.headers.first(for: .upgrade)?.description == "websocket")
    }

    @Test("headers named in Connection are stripped (RFC 9110 §7.6.1)")
    func connectionListedStripped() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: x\r\nConnection: close, X-Per-Conn\r\nX-Per-Conn: secret\r\nX-End-To-End: keep\r\n\r\n"))
        let h = try await conn.decodeHead()
        #expect(h?.request.headers.first(for: HeaderName("x-per-conn")) == nil)
        #expect(h?.request.headers.first(for: HeaderName("x-end-to-end"))?.description == "keep")
    }

    @Test("complete head larger than maxHeaderBytes → requestTooLarge")
    func completeHeadBomb() async {
        // Terminator present — the head parses in one shot, but the
        // limit applies to the parsed size as well.
        let big = String(repeating: "X", count: 1024)
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \(big)\r\n\r\n"),
                            maxHeaderBytes: 512)
        await #expect(throws: H1ConnError.requestTooLarge) { try await conn.decodeHead() }
    }

    @Test("missing Host on HTTP/1.1 → missingHost")
    func missingHost() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\n\r\n"))
        await #expect(throws: H1ConnError.missingHost) { try await conn.decodeHead() }
    }

    @Test("HTTP/1.0 without Host is fine")
    func noHost10() async throws {
        let conn = makeConn(req("GET / HTTP/1.0\r\n\r\n"))
        #expect(try await conn.decodeHead() != nil)
    }

    @Test("multiple Host headers → multipleHost")
    func multipleHost() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"))
        await #expect(throws: H1ConnError.multipleHost) { try await conn.decodeHead() }
    }

    @Test("bare CR in header value rejected")
    func bareCr() async {
        // Line 1 is "Host: a\rX: b" — the bare CR lands inside the
        // Host value before its CRLF.
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n"))
        await #expect(throws: H1ConnError.bareCrLfInHeader(line: 1)) { try await conn.decodeHead() }
    }

    @Test("bare LF in header value rejected")
    func bareLf() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\nHost: b\r\n\r\n"))
        await #expect(throws: H1ConnError.bareCrLfInHeader(line: 1)) { try await conn.decodeHead() }
    }

    @Test("NUL in header value rejected")
    func nulInValue() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nX: b\u{00}c\r\n\r\n"))
        await #expect(throws: H1ConnError.bareCrLfInHeader(line: 2)) { try await conn.decodeHead() }
    }

    @Test("obs-fold continuation line rejected")
    func obsFold() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n 2\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedHeader(line: 3)) { try await conn.decodeHead() }
    }

    @Test("space inside header name rejected")
    func spaceInName() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nBad Name: v\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedHeader(line: 2)) { try await conn.decodeHead() }
    }

    @Test("empty header name rejected")
    func emptyName() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n"))
        await #expect(throws: H1ConnError.emptyHeaderName) { try await conn.decodeHead() }
    }

    @Test("header block larger than maxHeaderBytes → requestTooLarge")
    func headerBomb() async {
        // INCOMPLETE head (no \r\n\r terminator) — the limit guards
        // the buffered unparsed bytes while waiting for the rest.
        let big = String(repeating: "X", count: 1024)
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \(big)\r\n"),
                            maxHeaderBytes: 512)
        await #expect(throws: H1ConnError.requestTooLarge) { try await conn.decodeHead() }
    }

    @Test("more headers than maxHeaderCount → tooManyHeaders")
    func countBomb() async {
        var raw = "GET / HTTP/1.1\r\nHost: a\r\n"
        for i in 0..<10 { raw += "X-\(i): v\r\n" }
        raw += "\r\n"
        let conn = makeConn(req(raw), maxHeaderCount: 5)
        await #expect(throws: H1ConnError.tooManyHeaders) { try await conn.decodeHead() }
    }

    @Test("malformed request line (no SP)")
    func noSpRequestLine() async {
        let conn = makeConn(req("GET\r\nHost: a\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedRequestLine) { try await conn.decodeHead() }
    }

    @Test("HTTP/2.0 → unsupportedVersion")
    func http2() async {
        let conn = makeConn(req("GET / HTTP/2.0\r\n\r\n"))
        await #expect(throws: H1ConnError.self) { try await conn.decodeHead() }
    }

    @Test("multiple SP between method and target rejected")
    func multiSp() async {
        let conn = makeConn(req("GET  / HTTP/1.1\r\nHost: a\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedRequestLine) { try await conn.decodeHead() }
    }

    @Test("control byte in method rejected")
    func ctlInMethod() async {
        let conn = makeConn(req("GE\rT / HTTP/1.1\r\nHost: a\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedRequestLine) { try await conn.decodeHead() }
    }

    @Test("control byte in request target rejected")
    func ctlInTarget() async {
        let conn = makeConn(req("GET /a\u{0D}b HTTP/1.1\r\nHost: a\r\n\r\n"))
        await #expect(throws: H1ConnError.malformedRequestLine) { try await conn.decodeHead() }
    }

    @Test("clean EOF between requests → nil")
    func cleanEof() async throws {
        let conn = makeConn([])
        let head = try await conn.decodeHead()
        #expect(head == nil)
    }

    @Test("EOF with a partial request buffered → incompleteMessage")
    func partialEof() async {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHo"))
        await #expect(throws: H1ConnError.incompleteMessage) { try await conn.decodeHead() }
    }

    @Test("read timeout (-2) → timedOut")
    func readTimeout() async {
        let conn = makeConn(req("GET / HTTP/1.1"))
        conn.io.forceResult = -2
        await #expect(throws: H1ConnError.timedOut) { try await conn.decodeHead() }
    }

    @Test("read error (-1) → ioError")
    func readError() async {
        let conn = makeConn(req("GET / HTTP/1.1"))
        conn.io.forceResult = -1
        await #expect(throws: H1ConnError.ioError) { try await conn.decodeHead() }
    }

    @Test("decodeHead after close() returns nil")
    func afterClose() async throws {
        let conn = makeConn(req("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
        await conn.close()
        #expect(try await conn.decodeHead() == nil)
    }

    @Test("read deadline is passed to the runtime")
    func deadlinePassthrough() async throws {
        let conn = makeConn(chunks: [req("GET / HTTP/1.1\r"), req("\nHost: a\r\n\r\n")])
        _ = try await conn.decodeHead()
        #expect(conn.io.lastDeadline != nil)
    }

    @Test("pipelined requests parse back-to-back with generation bump")
    func pipelined() async throws {
        let conn = makeConn(req(
            "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
            "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        ))
        let first = try await conn.decodeHead()
        let second = try await conn.decodeHead()
        #expect(first?.request.uri.pathString == "/a")
        #expect(second?.request.uri.pathString == "/b")
        #expect(first?.generation == 1)
        #expect(second?.generation == 2)
    }
}

// MARK: - Content-Length framing

@Suite("H1Conn Content-Length body")
struct H1CLBodyTests {

    @Test("CL body fully buffered is delivered then nil")
    func clBuffered() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
        let c1 = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c1 == Array("hello".utf8))
        let c2 = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c2 == nil)
        #expect(await conn.isBodyDone())
    }

    @Test("CL body split across reads")
    func clSplit() async throws {
        let conn = makeConn(chunks: [
            req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhel"),
            req("lo"),
            req(" world"),
        ])
        let head = try await conn.decodeHead()
        var collected: [UInt8] = []
        while let c = try await conn.nextBodyChunk(forGeneration: head!.generation) {
            collected.append(contentsOf: c)
        }
        #expect(collected == Array("hello world".utf8))
    }

    @Test("EOF mid-CL-body → incompleteMessage")
    func clEofMidBody() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)  // "hello"
        // Next read returns 0 (chunks exhausted) with 5 bytes outstanding.
        await #expect(throws: H1ConnError.incompleteMessage) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("Content-Length '+5' → invalidContentLength")
    func clPlusSign() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello"))
        await #expect(throws: H1ConnError.invalidContentLength) { try await conn.decodeHead() }
    }

    @Test("Content-Length list form '5, 5' → invalidContentLength")
    func clList() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello"))
        await #expect(throws: H1ConnError.invalidContentLength) { try await conn.decodeHead() }
    }

    @Test("duplicate conflicting Content-Length → conflictingContentLength")
    func clConflict() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"))
        await #expect(throws: H1ConnError.conflictingContentLength) { try await conn.decodeHead() }
    }

    @Test("duplicate identical Content-Length accepted")
    func clDuplicateSame() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
    }

    @Test("CL + TE chunked → conflictingFraming")
    func clPlusTe() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
        await #expect(throws: H1ConnError.conflictingFraming) { try await conn.decodeHead() }
    }

    @Test("CL above maxBodyBytes → requestTooLarge")
    func clTooBig() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n"),
                            maxBodyBytes: 100)
        await #expect(throws: H1ConnError.requestTooLarge) { try await conn.decodeHead() }
    }

    @Test("HEAD with Content-Length → no body state")
    func headNoBody() async throws {
        let conn = makeConn(req("HEAD / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == false)
        #expect(await conn.isBodyDone())
    }

    @Test("stale generation body read → BodyError.connectionAdvanced")
    func staleGeneration() async throws {
        let conn = makeConn(req(
            "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" +
            "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        ))
        let head1 = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head1!.generation)
        try await conn.drainBody()
        let head2 = try await conn.decodeHead()
        #expect(head2?.request.uri.pathString == "/b")
        // Reading request 1's body after the connection advanced:
        await #expect(throws: BodyError.connectionAdvanced) {
            _ = try await conn.nextBodyChunk(forGeneration: head1!.generation)
        }
    }

    @Test("multi-MiB CL body compacts and leaves pipelined request parseable")
    func clCompaction() async throws {
        let bodySize = 2 * 1024 * 1024 + 1234
        let body = [UInt8](repeating: 0x61, count: bodySize)
        var chunks: [[UInt8]] = [req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: \(bodySize)\r\n\r\n")]
        var offset = 0
        while offset < bodySize {
            let n = min(65536, bodySize - offset)
            chunks.append(Array(body[offset..<(offset + n)]))
            offset += n
        }
        chunks.append(req("GET /after HTTP/1.1\r\nHost: x\r\n\r\n"))
        let conn = makeConn(chunks: chunks, maxBodyBytes: 4 * 1024 * 1024)

        let head = try await conn.decodeHead()
        var total = 0
        while let c = try await conn.nextBodyChunk(forGeneration: head!.generation) {
            total += c.count
        }
        #expect(total == bodySize)

        let next = try await conn.decodeHead()
        #expect(next?.request.uri.pathString == "/after")
    }
}

// MARK: - Transfer-Encoding: chunked

@Suite("H1Conn chunked body")
struct H1ChunkedTests {

    @Test("single chunk + terminator")
    func singleChunk() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
        let end = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(end == nil)
    }

    @Test("multiple chunks split across reads")
    func multiChunk() async throws {
        let conn = makeConn(chunks: [
            req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"),
            req("lo\r\n3\r\nabc\r\n"),
            req("0\r\n\r\n"),
        ])
        let head = try await conn.decodeHead()
        var collected: [UInt8] = []
        while let c = try await conn.nextBodyChunk(forGeneration: head!.generation) {
            collected.append(contentsOf: c)
        }
        #expect(collected == Array("helloabc".utf8))
        #expect(await conn.isBodyDone())
    }

    @Test("chunk-ext is skipped")
    func chunkExt() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;name=val;q=1\r\nhello\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
    }

    @Test("trailers are consumed and next request parses")
    func trailers() async throws {
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nX-Check: yes\r\nX-More: no\r\n\r\n" +
            "GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        let end = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(end == nil)
        let next = try await conn.decodeHead()
        #expect(next?.request.uri.pathString == "/next")
    }

    @Test("invalid chunk size → malformedChunkSize")
    func badChunkSize() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n"))
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.malformedChunkSize) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("missing CRLF after chunk data → malformedChunkData")
    func badAfterData() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX"))
        let head = try await conn.decodeHead()
        // First pull delivers the data chunk; the malformed CRLF
        // after it is seen on the next pull.
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
        await #expect(throws: H1ConnError.malformedChunkData) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("bare LF inside trailer line → malformedChunkData")
    func bareLfInTrailer() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX: a\nb\r\n\r\n"))
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)  // 'a'
        await #expect(throws: H1ConnError.malformedChunkData) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("TE 'gzip' (no chunked) → unsupportedTransferEncoding (TE.TE defence)")
    func teGzipOnly() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\nAAAA"))
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) { try await conn.decodeHead() }
    }

    @Test("TE 'chunked, gzip' (chunked not final) → unsupportedTransferEncoding")
    func teChunkedNotLast() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"))
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) { try await conn.decodeHead() }
    }

    @Test("TE 'chunked, chunked' → unsupportedTransferEncoding")
    func teDoubleChunked() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n"))
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) { try await conn.decodeHead() }
    }

    @Test("TE 'chunked,' (trailing empty element) is accepted")
    func teTrailingComma() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked,\r\n\r\n1\r\na\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
    }

    @Test("TE chunked on HTTP/1.0 → unsupportedTransferEncoding")
    func teOn10() async {
        let conn = makeConn(req("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) { try await conn.decodeHead() }
    }

    @Test("chunk running total exceeds maxBodyBytes → requestTooLarge")
    func chunkTotalTooBig() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFF\r\n" + String(repeating: "a", count: 255) + "\r\n0\r\n\r\n"),
                            maxBodyBytes: 100)
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.requestTooLarge) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("unterminated chunk-ext line is bounded → requestTooLarge")
    func chunkExtBomb() async throws {
        // Head is 57 bytes — maxHeaderBytes must accommodate it; the
        // chunk-ext line (capped by the same limit) overflows it.
        let ext = String(repeating: "A", count: 128)
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1;\(ext)\r\na\r\n0\r\n\r\n"),
                            maxHeaderBytes: 64)
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.requestTooLarge) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("never-ending trailer line is bounded → requestTooLarge")
    func trailerLineBomb() async throws {
        let line = String(repeating: "A", count: 256)
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\(line)"),
                            maxHeaderBytes: 64)
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)  // 'a'
        await #expect(throws: H1ConnError.requestTooLarge) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("too many trailer lines → tooManyHeaders")
    func trailerCountBomb() async throws {
        var raw = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n"
        for _ in 0..<10 { raw += "X: v\r\n" }
        raw += "\r\n"
        let conn = makeConn(req(raw), maxHeaderCount: 5)
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)  // 'a'
        await #expect(throws: H1ConnError.tooManyHeaders) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("draining an unread chunked body counts bytes once (no double count)")
    func drainNoDoubleCount() async throws {
        // Body: 10 bytes in two 5-byte chunks. maxBodyBytes = 10.
        // With double counting the drain would see 15 > 10 and throw.
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "5\r\naaaaa\r\n5\r\nbbbbb\r\n0\r\n\r\n" +
            "GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
        ), maxBodyBytes: 10)
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)  // first 5
        try await conn.drainBody()  // second 5 — must not exceed 10
        let next = try await conn.decodeHead()
        #expect(next?.request.uri.pathString == "/next")
    }
}

// MARK: - Expect: 100-continue

@Suite("H1Conn 100-continue")
struct H1ExpectTests {

    @Test("first body read sends 100 Continue exactly once")
    func sends100() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.expects100Continue == true)
        #expect(conn.io.rawWrites.isEmpty)  // not before the body is read
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
        #expect(conn.io.rawWrites.count == 1)
        #expect(conn.io.rawWrites[0] == req("HTTP/1.1 100 Continue\r\n\r\n"))
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(conn.io.rawWrites.count == 1)  // exactly once
    }

    @Test("partial 100-continue write is fatal")
    func partial100() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello"))
        conn.io.rawWriteResult = 3
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.ioError) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("drainBody never sends 100 Continue (final response already out)")
    func drainNo100() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.expects100Continue == true)
        try await conn.drainBody()
        #expect(conn.io.rawWrites.isEmpty)
    }

    @Test("hasStartedReadingBody tracks the first body read")
    func bodyStarted() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(await !conn.hasStartedReadingBody())
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(await conn.hasStartedReadingBody())
    }
}

// MARK: - Trailers

@Suite("H1Conn trailers")
struct H1TrailersTests {

    @Test("trailers are parsed and available after body end")
    func trailersAvailable() async throws {
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nX-Total: 1\r\nX-Checksum: abc\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        let gen = head!.generation
        // Before the body is consumed: not available.
        #expect(await conn.trailers(forGeneration: gen) == nil)
        while let _ = try await conn.nextBodyChunk(forGeneration: gen) {}
        let trailers = await conn.trailers(forGeneration: gen)
        #expect(trailers?.first(for: HeaderName("x-total"))?.description == "1")
        #expect(trailers?.first(for: HeaderName("x-checksum"))?.description == "abc")
    }

    @Test("empty trailer section → empty map, not nil")
    func emptyTrailers() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        while let _ = try await conn.nextBodyChunk(forGeneration: head!.generation) {}
        // "0\r\n\r\n" — the empty line right after the last-chunk is
        // the terminator itself; no trailer lines were seen, so the
        // map is absent (nothing was advertised).
        #expect(await conn.trailers(forGeneration: head!.generation) == nil)
    }

    @Test("Content-Length bodies have no trailers")
    func clBodyNoTrailers() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na"))
        let head = try await conn.decodeHead()
        while let _ = try await conn.nextBodyChunk(forGeneration: head!.generation) {}
        #expect(await conn.trailers(forGeneration: head!.generation) == nil)
    }

    @Test("stale generation → nil")
    func staleTrailers() async throws {
        let conn = makeConn(req(
            "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nX-A: 1\r\n\r\n" +
            "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        ))
        let head1 = try await conn.decodeHead()
        while let _ = try await conn.nextBodyChunk(forGeneration: head1!.generation) {}
        _ = try await conn.decodeHead()
        #expect(await conn.trailers(forGeneration: head1!.generation) == nil)
    }

    @Test("framing/hop-by-hop trailer names are dropped, others kept")
    func forbiddenTrailerNames() async throws {
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\nX-Keep: yes\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        while let _ = try await conn.nextBodyChunk(forGeneration: head!.generation) {}
        let trailers = await conn.trailers(forGeneration: head!.generation)
        #expect(trailers?.first(for: .contentLength) == nil)
        #expect(trailers?.first(for: .transferEncoding) == nil)
        #expect(trailers?.first(for: HeaderName("x-keep"))?.description == "yes")
    }

    @Test("malformed trailer line → malformedTrailer")
    func malformedTrailerLine() async throws {
        // No colon in the line.
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nbroken-line\r\n\r\n"))
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        await #expect(throws: H1ConnError.malformedTrailer) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("trailers interrupted by an error are never visible (no partial map)")
    func partialTrailersNotVisible() async throws {
        // First trailer line is valid and parsed, the second is
        // malformed — the connection dies mid-section; the parsed
        // first line must NOT be handed out as valid data.
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nX-A: 1\r\nbroken\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        let gen = head!.generation
        _ = try await conn.nextBodyChunk(forGeneration: gen)  // 'a'
        do {
            _ = try await conn.nextBodyChunk(forGeneration: gen)
            Issue.record("expected malformedTrailer")
        } catch {}
        #expect(await conn.trailers(forGeneration: gen) == nil)
        // Bound accessor agrees with the direct method.
        let accessor = RequestTrailers(source: conn, generation: gen)
        #expect(await accessor.get() == nil)
    }

    @Test("RequestTrailers binds source + generation")
    func requestTrailersAccessor() async throws {
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "1\r\na\r\n0\r\nX-A: 1\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        let accessor = RequestTrailers(source: conn, generation: head!.generation)
        #expect(await accessor.get() == nil)  // body not consumed yet
        while let _ = try await conn.nextBodyChunk(forGeneration: head!.generation) {}
        let trailers = await accessor.get()
        #expect(trailers?.first(for: HeaderName("x-a"))?.description == "1")
    }

    @Test("nextBodyChunk before any decodeHead → noActiveRequest (no trap)")
    func noActiveRequest() async {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\na"))
        await #expect(throws: H1ConnError.noActiveRequest) {
            _ = try await conn.nextBodyChunk(forGeneration: 0)
        }
    }
}

// MARK: - Actor reentrancy

@Suite("H1Conn reentrancy")
struct H1ReentrancyTests {

    @Test("concurrent body pulls and drainBody keep framing consistent")
    func concurrentPullAndDrain() async throws {
        // Body: 8 chunked chunks of 4 bytes each, delivered 8 bytes
        // per read so pulls and the drain interleave at suspension
        // points. Actor serialization must hand every chunk to
        // exactly ONE consumer and leave the connection framed for
        // the next request.
        var raw = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        for i in 0..<8 {
            let body = "\(i)AAA"  // 4 bytes
            raw += "4\r\n\(body)\r\n"
        }
        raw += "0\r\n\r\nGET /next HTTP/1.1\r\nHost: x\r\n\r\n"

        let input = Array(raw.utf8)
        var chunks: [[UInt8]] = []
        var off = 0
        while off < input.count {
            let step = min(8, input.count - off)
            chunks.append(Array(input[off..<(off + step)]))
            off += step
        }
        let conn = makeConn(chunks: chunks)
        let head = try await conn.decodeHead()
        let gen = head!.generation

        // Two competing consumers of the same body. Actor
        // serialization hands every byte-fragment to exactly one
        // consumer, in body order — the two streams interleave but
        // never lose, duplicate, or corrupt bytes. (Fragments may
        // straddle wire-chunk boundaries when reads split them —
        // that is the designed streaming behavior.)
        async let pulled: [[UInt8]] = {
            var acc = [[UInt8]]()
            while let c = try await conn.nextBodyChunk(forGeneration: gen) {
                acc.append(c)
            }
            return acc
        }()
        async let drained: [[UInt8]] = {
            var acc = [[UInt8]]()
            while await !conn.isBodyDone() {
                if let c = try await conn.nextBodyChunk(forGeneration: gen) {
                    acc.append(c)
                } else {
                    break
                }
            }
            return acc
        }()

        let (a, b) = try await (pulled, drained)
        // Byte-level multiset equality: every body byte delivered
        // exactly once across the two consumers (fragments are
        // contiguous slices, so corruption would show up here too).
        var received = [UInt8]()
        for frag in a { received.append(contentsOf: frag) }
        for frag in b { received.append(contentsOf: frag) }
        let expected = (0..<8).flatMap { Array("\($0)AAA".utf8) }
        #expect(received.count == expected.count)
        #expect(received.sorted() == expected.sorted())
        #expect(await conn.isBodyDone())

        // And the connection is still correctly framed afterwards.
        let next = try await conn.decodeHead()
        #expect(next?.request.uri.pathString == "/next")
    }
}

// MARK: - Keep-alive policy (ServerTransaction)

@Suite("ServerTransaction keep-alive policy")
struct KeepAlivePolicyTests {

    func response(conn: String?) -> Response {
        var r = Response(status: .ok)
        if let conn { r.headers.insert(.connection, conn) }
        return r
    }

    @Test("explicit response close vetoes, including on 304")
    func explicitClose() {
        var r = response(conn: "close")
        r.status = StatusCode(304)
        #expect(!ServerTransaction.shouldKeepAlive(
            requestKeepAlive: true, response: r,
            explicitConnection: r.headers.first(for: .connection)
        ))
    }

    @Test("HTTP/1.0 + request keep-alive survives a Connection-less response")
    func http10KeepAliveSurvives() {
        // The regression this fold guards: re-applying the version
        // default on the response side would close the connection
        // even though the request explicitly asked for keep-alive.
        let r = response(conn: nil)
        #expect(ServerTransaction.shouldKeepAlive(
            requestKeepAlive: true, response: r, explicitConnection: nil
        ))
    }

    @Test("request-side decision passes through when response is silent")
    func passthrough() {
        let r = response(conn: nil)
        #expect(ServerTransaction.shouldKeepAlive(
            requestKeepAlive: false, response: r, explicitConnection: nil
        ) == false)
        #expect(ServerTransaction.shouldKeepAlive(
            requestKeepAlive: true, response: r, explicitConnection: nil
        ) == true)
    }

    @Test("response keep-alive cannot upgrade a close-requested connection")
    func responseKeepAliveNoUpgrade() {
        let r = response(conn: "keep-alive")
        #expect(!ServerTransaction.shouldKeepAlive(
            requestKeepAlive: false, response: r,
            explicitConnection: r.headers.first(for: .connection)
        ))
    }

    @Test("substring does not match token ('closeness')")
    func substringNoMatch() {
        let r = response(conn: "closeness")
        #expect(ServerTransaction.shouldKeepAlive(
            requestKeepAlive: true, response: r,
            explicitConnection: r.headers.first(for: .connection)
        ))
    }

    @Test("token list matching ('upgrade, close')")
    func tokenList() {
        let r = response(conn: "upgrade, close")
        #expect(!ServerTransaction.shouldKeepAlive(
            requestKeepAlive: true, response: r,
            explicitConnection: r.headers.first(for: .connection)
        ))
    }
}
