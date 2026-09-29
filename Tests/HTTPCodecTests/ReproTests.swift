import Testing
import Foundation
import HTTP
@testable import HTTPCodec

/// Regression: pipelined chunked bodies delivered in large chunks —
/// exercises the view fast path + tail accumulation + mid-body
/// compaction. Chunk sizes on the wire are HEX: "200\r\n" is
/// 0x200 = 512 bytes.
@Test("pipelined chunked bodies through large-chunk delivery")
func pipelinedChunkedLargeChunks() async throws {
    let dataSize = 512
    var oneChunk = Array(String(dataSize, radix: 16).utf8)
    oneChunk.append(contentsOf: [0x0D, 0x0A])
    oneChunk.append(contentsOf: [UInt8](repeating: 0x62, count: dataSize))
    oneChunk.append(contentsOf: [0x0D, 0x0A])
    let headText = "POST /api/upload HTTP/1.1\r\nHost: bench.local\r\n"
        + "Transfer-Encoding: chunked\r\n\r\n"
    let head = Array(headText.utf8)
    let term = Array("0\r\n\r\n".utf8)
    var stream = [UInt8]()
    for _ in 0..<50 {
        stream.append(contentsOf: head)
        for _ in 0..<8 { stream.append(contentsOf: oneChunk) }
        stream.append(contentsOf: term)
    }
    var chunks: [[UInt8]] = []
    var off = 0
    while off < stream.count {
        chunks.append(Array(stream[off..<min(off + 65536, stream.count)]))
        off += 65536
    }
    let conn = makeConn(chunks: chunks)
    var bodies = 0
    while let h = try await conn.decodeHead() {
        while let c = try await conn.nextBodyChunk(forGeneration: h.generation) {
            bodies += c.count
        }
    }
    #expect(bodies == 50 * 8 * dataSize)
}
