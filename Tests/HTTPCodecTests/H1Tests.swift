//===----------------------------------------------------------------------===//
//
//  H1Tests.swift
//  HyperTests
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTP
@testable import HTTPCodec

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
