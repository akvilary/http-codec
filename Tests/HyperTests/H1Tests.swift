//===----------------------------------------------------------------------===//
//
//  H1Tests.swift
//  HyperTests
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTP
@testable import Hyper

@Suite("H1 Decoder")
struct H1DecodeTests {

    @Test("Parse a minimal GET request")
    func minimalGet() throws {
        var decoder = H1Decoder()
        try decoder.feed([UInt8]("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8))
        let result = try decoder.decode()
        guard case .complete(let request) = result else {
            Issue.record("expected .complete, got \(result)")
            return
        }
        #expect(request.method == .GET)
        #expect(request.uri.pathString == "/")
        #expect(request.version == .http11)
        #expect(request.headers.first(for: .host)?.description == "localhost")
        #expect(request.body.isEmpty)
    }

    @Test("Parse a POST with body via Content-Length")
    func postWithBody() async throws {
        var decoder = H1Decoder()
        let raw = "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
        try decoder.feed([UInt8](raw.utf8))
        let result = try decoder.decode()
        guard case .complete(let request) = result else {
            Issue.record("expected .complete")
            return
        }
        #expect(request.method == .POST)
        if case .buffered(let b) = request.body {
            #expect(b.count == 5)
            #expect(String(decoding: b, as: UTF8.self) == "hello")
        } else {
            Issue.record("expected .buffered body")
        }
    }

    @Test("Parse a chunked Transfer-Encoding request body")
    func chunkedRequest() throws {
        var decoder = H1Decoder()
        // Two chunks: "hello" (5) + "world" (5), then terminating 0-chunk.
        let raw = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
                  "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
        try decoder.feed([UInt8](raw.utf8))
        let result = try decoder.decode()
        guard case .complete(let request) = result else {
            Issue.record("expected .complete")
            return
        }
        #expect(request.method == .POST)
        if case .buffered(let b) = request.body {
            #expect(String(decoding: b, as: UTF8.self) == "helloworld")
        } else {
            Issue.record("expected .buffered body from chunked")
        }
    }

    @Test("Return .needsMore on partial input")
    func partialInput() throws {
        var decoder = H1Decoder()
        try decoder.feed([UInt8]("GET / HTTP/1.1\r\nHost: local".utf8))
        let result = try decoder.decode()
        if case .complete = result {
            Issue.record("expected .needsMore on partial input")
        }
    }

    @Test("Pipeline: parse two requests from one feed")
    func pipelined() throws {
        var decoder = H1Decoder()
        let raw = "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        try decoder.feed([UInt8](raw.utf8))

        let r1 = try decoder.decode()
        guard case .complete(let req1) = r1 else { Issue.record("first parse failed"); return }
        #expect(req1.uri.pathString == "/a")

        let r2 = try decoder.decode()
        guard case .complete(let req2) = r2 else { Issue.record("second parse failed"); return }
        #expect(req2.uri.pathString == "/b")
    }
}

@Suite("H1 Encoder")
struct H1EncodeTests {

    @Test("Encode a 200 OK response with body")
    func encodeBasic() throws {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        let response = Response(
            status: .ok,
            headers: HeaderMap(),
            body: Body([0x68, 0x69])  // "hi"
        )
        let head = encoder.encodeHead(response, keepAlive: true, into: &buffer)
        let s = String(decoding: buffer, as: UTF8.self)
        #expect(head == .buffered)
        #expect(s.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(s.contains("Content-Length: 2"))
        #expect(s.contains("Connection: keep-alive"))
        // Body is NOT in the buffer — caller uses writev to write
        // header + body separately.
        #expect(!s.contains("hi"))
    }

    @Test("Encode Connection: close when keepAlive=false")
    func encodeClose() throws {
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        let response = Response(status: .notFound, body: Body("nope"))
        encoder.encodeHead(response, keepAlive: false, into: &buffer)
        let s = String(decoding: buffer, as: UTF8.self)
        #expect(s.hasPrefix("HTTP/1.1 404 Not Found\r\n"))
        #expect(s.contains("Connection: close"))
    }
}
