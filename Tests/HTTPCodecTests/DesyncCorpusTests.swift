//===----------------------------------------------------------------------===//
//
//  DesyncCorpusTests.swift
//  HTTPCodecTests
//
//  Curated request-smuggling / desync vectors — the shapes that
//  desync a lenient front-end from this (strict) back-end. Every
//  vector asserts an EXACT outcome (accept-with-framing or a
//  specific rejection), so any future parser change that flips one
//  fails loudly here.
//
//  Sources of the vector families: RFC 9112 §11 (message parsing
//  robustness), the classic CL.TE / TE.CL / TE.TE smuggling triads,
//  obs-fold and bare-LF line-ending tricks, chunk-size padding and
//  sign tricks, and quoted chunk-ext ambiguity (our behavior is
//  pinned to httparse: ext runs to the first CRLF, quotes are not
//  parsed — matching the strictest mainstream parser).
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTP
@testable import HTTPCodec

@Suite("Desync corpus")
struct DesyncCorpusTests {

    // MARK: - Content-Length tricks

    @Test("CL '+5' rejected (lenient Int parsers accept)")
    func clPlus() async {
        await #expect(throws: H1ConnError.invalidContentLength) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello")).decodeHead()
        }
    }

    @Test("CL '␣5' accepted — OWS after ':' is universally stripped (not a vector)")
    func clLeadingOws() async throws {
        // RFC 9110 §5.5: optional whitespace around the field-value is
        // removed by every conformant parser, so this can never desync
        // peers. Anchor the acceptance explicitly.
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length:  5\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
    }

    @Test("CL list '0, 5' rejected")
    func clListSmuggle() async {
        await #expect(throws: H1ConnError.invalidContentLength) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0, 5\r\n\r\nhello")).decodeHead()
        }
    }

    @Test("CL duplicate different values rejected (either order)")
    func clDupDifferent() async {
        await #expect(throws: H1ConnError.conflictingContentLength) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello")).decodeHead()
        }
        await #expect(throws: H1ConnError.conflictingContentLength) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\nhello")).decodeHead()
        }
    }

    @Test("CL '005' accepted as 5 (value-equal duplicates, hyper parity)")
    func clPadding() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 005\r\n\r\nhello"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
        let body = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(body == Array("hello".utf8))
    }

    // MARK: - CL.TE / TE.CL / TE.TE triads

    @Test("CL.TE rejected in both header orders")
    func clTe() async {
        for raw in [
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
        ] {
            await #expect(throws: H1ConnError.conflictingFraming) {
                _ = try await makeConn(req(raw)).decodeHead()
            }
        }
    }

    @Test("TE.TE: 'chunked, identity' rejected (chunked not final)")
    func teTeIdentityLast() async {
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n")).decodeHead()
        }
    }

    @Test("TE 'identity, chunked' accepted (legal final-chunked)")
    func teIdentityChunked() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity, chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("a".utf8))
    }

    @Test("TE case tricks: 'Chunked' accepted (codings are case-insensitive tokens)")
    func teCase() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == true)
    }

    @Test("TE split across two headers concatenates both ways")
    func teSplitHeaders() async throws {
        // "gzip" then "chunked" → combined list ends in chunked → legal.
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("a".utf8))

        // "chunked" then "gzip" → combined list ends in gzip → reject.
        await #expect(throws: H1ConnError.unsupportedTransferEncoding) {
            _ = try await makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n")).decodeHead()
        }
    }

    // MARK: - Line-ending tricks

    @Test("bare-LF request line rejected (CRLF-only framing)")
    func bareLfRequestLine() async {
        await #expect(throws: H1ConnError.self) {
            _ = try await makeConn(req("GET / HTTP/1.1\nHost: x\n\n")).decodeHead()
        }
    }

    @Test("space before colon rejected ('Host : x' — name token violation)")
    func spaceBeforeColon() async {
        await #expect(throws: H1ConnError.malformedHeader(line: 1)) {
            _ = try await makeConn(req("GET / HTTP/1.1\r\nHost : x\r\n\r\n")).decodeHead()
        }
    }

    // MARK: - Chunk framing tricks

    @Test("chunk size '-5' rejected")
    func chunkNegative() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nhello"))
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.malformedChunkSize) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("chunk size '0x5' rejected (no 0x prefix)")
    func chunkHexPrefix() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello"))
        let head = try await conn.decodeHead()
        await #expect(throws: H1ConnError.malformedChunkSize) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("chunk size '05' accepted as 5 (leading-zero padding is legal)")
    func chunkPad() async throws {
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n05\r\nhello\r\n0\r\n\r\n"))
        let head = try await conn.decodeHead()
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
    }

    @Test("bare-LF in chunk-size line rejected")
    func trailerBareLf() async throws {
        // "0\n\r\n": the size-line scan includes the bare LF in the
        // size bytes → not hex → malformedChunkSize. A parser
        // treating bare LF as a line terminator would frame the
        // remainder differently — pinned strict.
        let conn = makeConn(req("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\n\r\n"))
        let head = try await conn.decodeHead()
        _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        await #expect(throws: H1ConnError.malformedChunkSize) {
            _ = try await conn.nextBodyChunk(forGeneration: head!.generation)
        }
    }

    @Test("quoted chunk-ext containing CRLF: ext ends at first CRLF (httparse pin)")
    func chunkExtQuotedCrlf() async throws {
        // ext = `a="b` — the quote does NOT protect the CRLF: the
        // size line ends at the first CRLF, data starts after.
        // Parsers that honor quoted strings would frame differently
        // → desync vector; we pin to the strictest reading.
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "5;a=\"b\r\nhello\r\n0\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        let c = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(c == Array("hello".utf8))
        let end = try await conn.nextBodyChunk(forGeneration: head!.generation)
        #expect(end == nil)
    }

    // MARK: - Ambiguity anchors

    @Test("POST with neither CL nor TE → no body; trailing bytes are the next request")
    func noFramingMeansNoBody() async throws {
        let conn = makeConn(req(
            "POST / HTTP/1.1\r\nHost: x\r\n\r\n" +
            "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
        ))
        let head = try await conn.decodeHead()
        #expect(head?.hasBody == false)
        // The "body" a lenient parser might attach is parsed here as
        // the next request — the behavior every strict peer expects.
        let next = try await conn.decodeHead()
        #expect(next?.request.uri.pathString == "/smuggled")
    }
}
