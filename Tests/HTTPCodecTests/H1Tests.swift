//===----------------------------------------------------------------------===//
//
//  H1Tests.swift
//  HTTPCodecTests
//
//  Regression suite for the H1 response encoder: framing policy,
//  header validation (response-splitting defence), status-specific
//  suppression rules, Date emission.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTPModel
@testable import HTTPCodec

@Suite("H1 Encoder")
struct H1EncodeTests {

    /// Decode the head buffer for assertion-friendly string checks.
    func headString(_ buffer: [UInt8]) -> String {
        // Head only — cut at the first \r\n\r\n if present.
        var s = String(decoding: buffer, as: UTF8.self)
        if let r = s.range(of: "\r\n\r\n") { s = String(s[..<r.lowerBound]) }
        return s
    }

    // MARK: - Basic framing

    @Test("Encode a 200 OK response with body")
    func encodeBasic() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let response = Response(
            status: .ok,
            headers: HeaderMap(),
            body: Body([0x68, 0x69])  // "hi"
        )
        let head = try encoder.encodeHead(response, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .buffered)
        #expect(s.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(s.contains("Content-Length: 2"))
        #expect(s.contains("Connection: keep-alive"))
        // Body is NOT in the buffer — caller uses writev to write
        // header + body separately.
        #expect(!s.contains("hi"))
        // Head is properly terminated.
        #expect(String(decoding: buffer, as: UTF8.self).hasSuffix("\r\n\r\n"))
    }

    @Test("Encode Connection: close when keepAlive=false")
    func encodeClose() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let response = Response(status: .notFound, body: Body("nope"))
        try encoder.encodeHead(response, keepAlive: false, into: &buffer)
        let s = headString(buffer)
        #expect(s.hasPrefix("HTTP/1.1 404 Not Found\r\n"))
        #expect(s.contains("Connection: close"))
    }

    @Test("Empty body emits Content-Length: 0")
    func encodeEmpty() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let head = try encoder.encodeHead(Response(status: .ok), keepAlive: true, into: &buffer)
        #expect(head == .noBody)
        #expect(headString(buffer).contains("Content-Length: 0"))
    }

    @Test("204 emits no framing headers")
    func encode204() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: StatusCode(204))
        r.headers.insert(.contentLength, "5")  // handler bug — dropped
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .noBody)
        #expect(!s.contains("Content-Length"))
        #expect(!s.contains("Transfer-Encoding"))
    }

    @Test("1xx emits no framing headers")
    func encode1xx() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let head = try encoder.encodeHead(Response(status: StatusCode(100)), keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .noBody)
        #expect(!s.contains("Content-Length"))
        #expect(!s.contains("Transfer-Encoding"))
    }

    @Test("304 forwards user Content-Length verbatim")
    func encode304() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: StatusCode(304))
        r.headers.insert(.contentLength, "1234")
        r.headers.insert(.etag, "\"x\"")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .noBody)
        #expect(s.contains("Content-Length: 1234"))
        #expect(s.contains("Etag: \"x\""))
    }

    // MARK: - HEAD

    @Test("HEAD preserves the Content-Length GET would produce")
    func headPreservesCL() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let response = Response(status: .ok, body: Body("hello"))
        let head = try encoder.encodeHead(response, keepAlive: true, requestMethod: .HEAD, into: &buffer)
        #expect(head == .noBody)
        #expect(headString(buffer).contains("Content-Length: 5"))
    }

    @Test("HEAD with user Content-Length forwards it verbatim")
    func headUserCL() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: .empty)
        r.headers.insert(.contentLength, "100")
        let head = try encoder.encodeHead(r, keepAlive: true, requestMethod: .HEAD, into: &buffer)
        #expect(head == .noBody)
        #expect(headString(buffer).contains("Content-Length: 100"))
    }

    @Test("HEAD with stream body emits no length")
    func headStream() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        let r = Response(status: .ok, body: .stream(stream))
        let head = try encoder.encodeHead(r, keepAlive: true, requestMethod: .HEAD, into: &buffer)
        let s = headString(buffer)
        #expect(head == .noBody)
        #expect(!s.contains("Content-Length"))
        #expect(!s.contains("Transfer-Encoding"))
    }

    // MARK: - Content-Length correctness

    @Test("user Content-Length contradicting buffered body → error")
    func clMismatch() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: Body("hello"))
        r.headers.insert(.contentLength, "3")
        #expect(throws: H1EncodeError.contentLengthMismatch(expected: 3, actual: 5)) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test("user Content-Length on empty body must be 0")
    func clEmptyMismatch() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: .empty)
        r.headers.insert(.contentLength, "5")
        #expect(throws: H1EncodeError.self) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test("matching user Content-Length is forwarded")
    func clMatch() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: Body("hello"))
        r.headers.insert(.contentLength, "5")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        #expect(head == .buffered)
        #expect(headString(buffer).contains("Content-Length: 5"))
    }

    @Test("non-digit user Content-Length → error")
    func clGarbage() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: Body("hello"))
        r.headers.entries.append((.contentLength, HeaderValue(bytes: Array("+5".utf8))))
        #expect(throws: H1EncodeError.invalidContentLength("+5")) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test("duplicate user Content-Length → error")
    func clDuplicate() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: Body("hello"))
        r.headers.append(.contentLength, "5")
        r.headers.append(.contentLength, "5")
        #expect(throws: H1EncodeError.self) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test(".pull response body is treated as empty")
    func pullBody() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let r = Response(status: .ok, body: .pull { nil })
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        #expect(head == .noBody)
        #expect(headString(buffer).contains("Content-Length: 0"))
    }

    // MARK: - Streaming

    @Test("stream body auto-chunks")
    func streamAutoChunked() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        let r = Response(status: .ok, body: .stream(stream))
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        #expect(head == .stream)
        #expect(headString(buffer).contains("Transfer-Encoding: chunked"))
    }

    @Test("user TE chunked is forwarded verbatim (no duplicate)")
    func streamUserTE() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        r.headers.insert(.transferEncoding, "chunked")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .stream)
        #expect(s.components(separatedBy: "Transfer-Encoding:").count - 1 == 1)
    }

    @Test("user TE non-chunked on stream body → error")
    func streamBadTE() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        r.headers.insert(.transferEncoding, "gzip")
        #expect(throws: H1EncodeError.self) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test("CRLF smuggled inside a non-final TE token → error (response splitting)")
    func streamTECrlfInjection() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        // Token analysis alone would accept this (chunked is final,
        // count == 1) — the CTL check must reject it first.
        r.headers.entries.append(
            (.transferEncoding, HeaderValue(bytes: Array("gzip\r\nX-Injected: 1, chunked".utf8)))
        )
        #expect(throws: H1EncodeError.invalidHeaderValue(name: "transfer-encoding")) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
        #expect(!String(decoding: buffer, as: UTF8.self).contains("X-Injected"))
    }

    @Test("user CL + stream body → streamIdentity")
    func streamIdentity() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        r.headers.insert(.contentLength, "10")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .streamIdentity(length: 10))
        #expect(s.contains("Content-Length: 10"))
        #expect(!s.contains("Transfer-Encoding"))
    }

    @Test("user CL 0 + stream body → noBody")
    func streamIdentityZero() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        r.headers.insert(.contentLength, "0")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        #expect(head == .noBody)
    }

    @Test("user TE chunked + user CL on stream → CL dropped, chunked wins")
    func streamTEWinsOverCL() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        let stream = AsyncThrowingStream<[UInt8], Error> { $0.finish() }
        var r = Response(status: .ok, body: .stream(stream))
        r.headers.insert(.transferEncoding, "chunked")
        r.headers.insert(.contentLength, "10")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .stream)
        #expect(!s.contains("Content-Length"))
        #expect(s.contains("Transfer-Encoding: chunked"))
    }

    @Test("encodeChunk + encodeEndOfChunks framing")
    func chunkFraming() throws {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        encoder.encodeChunk(Array("hello".utf8), into: &buffer)
        encoder.encodeEndOfChunks(into: &buffer)
        #expect(String(decoding: buffer, as: UTF8.self) == "5\r\nhello\r\n0\r\n\r\n")
    }

    // MARK: - Response-splitting defence

    @Test("CRLF in header value → error, nothing written for it")
    func crlfInjectionValue() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok)
        r.headers.entries.append((HeaderName("x-evil"), HeaderValue(bytes: Array("a\r\nX-Injected: 1".utf8))))
        #expect(throws: H1EncodeError.invalidHeaderValue(name: "x-evil")) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
        let s = String(decoding: buffer, as: UTF8.self)
        #expect(!s.contains("X-Injected"))
    }

    @Test("CRLF in header name → error")
    func crlfInjectionName() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok)
        r.headers.entries.append((HeaderName("X-Bad\r\nSet-Cookie: pwn=1"), HeaderValue("v")))
        #expect(throws: H1EncodeError.invalidHeaderName("x-bad\r\nset-cookie: pwn=1")) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    @Test("NUL in header value → error")
    func nulInjectionValue() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok)
        r.headers.entries.append((HeaderName("x-nul"), HeaderValue(bytes: [0x61, 0x00, 0x62])))
        #expect(throws: H1EncodeError.self) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    // MARK: - Connection / hop-by-hop

    @Test("user Connection is forwarded verbatim (no auto duplicate)")
    func userConnectionForwarded() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: .empty)
        r.headers.insert(.connection, "upgrade")
        try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(s.contains("Connection: upgrade"))
        #expect(s.components(separatedBy: "Connection:").count - 1 == 1)
    }

    @Test("hop-by-hop headers other than Connection/Upgrade are dropped")
    func hopByHopDropped() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: .empty)
        r.headers.insert(.keepAlive, "timeout=5")
        r.headers.insert(.trailer, "X")
        try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(!s.contains("Keep-Alive"))
        #expect(!s.contains("Trailer"))
    }

    @Test("Upgrade is forwarded (101 Switching Protocols handshake)")
    func upgradeForwarded() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: StatusCode(101), body: .empty)
        r.headers.insert(.connection, "upgrade")
        r.headers.insert(.upgrade, "websocket")
        let head = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(head == .noBody)
        #expect(s.hasPrefix("HTTP/1.1 101 Switching Protocols\r\n"))
        #expect(s.contains("Connection: upgrade"))
        #expect(s.contains("Upgrade: websocket"))
        // 1xx carries no framing headers.
        #expect(!s.contains("Content-Length"))
        #expect(!s.contains("Transfer-Encoding"))
    }

    @Test("101 without user Connection auto-emits 'Connection: upgrade'")
    func upgrade101AutoConnection() throws {
        // Handler set Upgrade but forgot Connection — the encoder
        // must not emit a nonsensical keep-alive on a protocol
        // switch (RFC 9110 §15.2.2).
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: StatusCode(101), body: .empty)
        r.headers.insert(.upgrade, "websocket")
        _ = try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(s.contains("Connection: upgrade"))
        #expect(!s.contains("Connection: keep-alive"))
        #expect(s.contains("Upgrade: websocket"))
    }

    @Test("duplicate Connection headers → error")
    func duplicateConnection() {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        var r = Response(status: .ok, body: .empty)
        r.headers.append(.connection, "keep-alive")
        r.headers.append(.connection, "close")
        #expect(throws: H1EncodeError.duplicateConnection) {
            try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        }
    }

    // MARK: - Date

    @Test("Date header emitted by default and suppressible by user")
    func dateHeader() throws {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        try encoder.encodeHead(Response(status: .ok), keepAlive: true, into: &buffer)
        let s = headString(buffer)
        #expect(s.contains("Date: "))
        #expect(s.contains(" GMT\r\n"))

        var buffer2: [UInt8] = []
        var r2 = Response(status: .ok)
        r2.headers.insert(.date, "Tue, 29 Sep 2026 00:00:00 GMT")
        try encoder.encodeHead(r2, keepAlive: true, into: &buffer2)
        #expect(headString(buffer2).components(separatedBy: "Date:").count - 1 == 1)
    }

    @Test("HTTPDateCache.format: known timestamps")
    func dateFormat() {
        #expect(String(decoding: HTTPDateCache.format(0), as: UTF8.self) == "Thu, 01 Jan 1970 00:00:00 GMT")
        // 2000-03-01 00:00:00 UTC = 951868800 — leap-year boundary.
        #expect(String(decoding: HTTPDateCache.format(951868800), as: UTF8.self) == "Wed, 01 Mar 2000 00:00:00 GMT")
    }

    // MARK: - Title-casing

    @Test("header names are title-cased")
    func titleCase() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        var buffer: [UInt8] = []
        var r = Response(status: .ok)
        r.headers.insert(HeaderName("x-custom-multi-part"), "v")
        try encoder.encodeHead(r, keepAlive: true, into: &buffer)
        #expect(headString(buffer).contains("X-Custom-Multi-Part: v"))
    }
}
