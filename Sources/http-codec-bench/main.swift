//===----------------------------------------------------------------------===//
//
//  main.swift
//  http-codec-bench
//
//  Codec-level micro-benchmarks: request-head parsing, CL/chunked
//  body framing, response encoding. Wall-clock medians over warm
//  runs — numbers, not vibes: they pinned the zero-alloc header
//  storage, the 16-byte SWAR scanners and the parse-from-view fast
//  path, and guard them against regressions.
//
//  Run: swift run -c release http-codec-bench
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTPModel
import HTTPCodec

// MARK: - Feeding I/O

/// Streams a prebuilt byte buffer in fixed-size chunks (the shape a
/// pulsar loop delivers), EOF at the end.
final class FeedIO: Http1ConnectionIO, @unchecked Sendable {
    private let lock = NSLock()
    private let bytes: [UInt8]
    private let chunkSize: Int
    private var offset = 0
    private var current: ArraySlice<UInt8> = []

    init(_ bytes: [UInt8], chunkSize: Int = 64 * 1024) {
        self.bytes = bytes
        self.chunkSize = chunkSize
    }

    func read(deadline: ContinuousClock.Instant?) async -> Int {
        readSync()
    }

    private func readSync() -> Int {
        lock.lock(); defer { lock.unlock() }
        guard offset < bytes.count else { return 0 }
        let n = min(chunkSize, bytes.count - offset)
        current = bytes[offset..<(offset + n)]
        offset += n
        return n
    }

    func readView(count: Int) -> UnsafeBufferPointer<UInt8> {
        lock.lock(); defer { lock.unlock() }
        // The buffer covers exactly the slice's elements, with a
        // 0-based index space (toolchain convention — verified), so
        // baseAddress IS the first delivered byte. No index
        // arithmetic: slices here start at arbitrary offsets.
        return current.withUnsafeBufferPointer { buf in
            UnsafeBufferPointer(start: buf.baseAddress, count: count)
        }
    }

    func writeRaw(_ bytes: [UInt8]) -> Int { bytes.count }
}

/// Serial executor over a private queue. Models the production
/// runtime: calls already ON the executor's thread execute INLINE
/// (like pulsar's `isSameExclusiveExecutionContext` fast path) —
/// only cross-thread calls pay the hop. Without this the benchmark
/// would measure DispatchQueue round-trips, not the codec.
final class BenchExecutor: SerialExecutor, TaskExecutor, @unchecked Sendable {
    private static let onQueueKey = DispatchSpecificKey<UInt8>()
    private let queue = DispatchQueue(label: "http-codec-bench")

    init() {
        queue.setSpecific(key: Self.onQueueKey, value: 1)
    }

    func asUnownedTaskExecutor() -> UnownedTaskExecutor {
        UnownedTaskExecutor(ordinary: self)
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        let executor = UnownedSerialExecutor(ordinary: self)
        queue.async { unowned.runSynchronously(on: executor) }
    }

    /// The production inline path: an actor call made from this
    /// executor's own thread executes as a direct call — no job, no
    /// hop (exactly how pulsar's PollEventLoop serves H1Conn from
    /// the loop-pinned driveConnection Task). Without this the
    /// benchmark measures executor round-trips instead of the codec.
    func isSameExclusiveExecutionContext(
        _ other: UnownedSerialExecutor
    ) -> Bool {
        DispatchQueue.getSpecific(key: Self.onQueueKey) == 1
    }
}

let benchExecutor = BenchExecutor()

// MARK: - Scenarios

func buildHeadStream(_ count: Int) -> [UInt8] {
    let requestText = "GET /api/users?page=1&size=20 HTTP/1.1\r\n"
        + "Host: bench.local\r\n"
        + "User-Agent: starlight-bench/1.0\r\n"
        + "Accept: application/json\r\n"
        + "Accept-Encoding: gzip, br\r\n"
        + "X-Request-Id: 0123456789abcdef\r\n"
        + "\r\n"
    let request = Array(requestText.utf8)
    var out = [UInt8]()
    out.reserveCapacity(request.count * count)
    for _ in 0..<count { out.append(contentsOf: request) }
    return out
}

func buildCLStream(_ count: Int, bodySize: Int) -> [UInt8] {
    let headText = "POST /api/items HTTP/1.1\r\nHost: bench.local\r\n"
        + "Content-Type: application/octet-stream\r\n"
        + "Content-Length: \(bodySize)\r\n\r\n"
    let head = Array(headText.utf8)
    var out = [UInt8]()
    out.reserveCapacity((head.count + bodySize) * count)
    for _ in 0..<count {
        out.append(contentsOf: head)
        out.append(contentsOf: [UInt8](repeating: 0x61, count: bodySize))
    }
    return out
}

func buildChunkedStream(_ count: Int, bodySize: Int) -> [UInt8] {
    let headText = "POST /api/upload HTTP/1.1\r\nHost: bench.local\r\n"
        + "Transfer-Encoding: chunked\r\n\r\n"
    let head = Array(headText.utf8)
    let chunkData = bodySize / 8
    // Chunk sizes are HEX on the wire (RFC 9112 §7.1).
    var oneChunk = Array(String(chunkData, radix: 16).utf8)
    oneChunk.append(contentsOf: [0x0D, 0x0A])
    oneChunk.append(contentsOf: [UInt8](repeating: 0x62, count: chunkData))
    oneChunk.append(contentsOf: [0x0D, 0x0A])
    let terminator = Array("0\r\n\r\n".utf8)
    var out = [UInt8]()
    out.reserveCapacity((head.count + 8 * oneChunk.count + terminator.count) * count)
    for _ in 0..<count {
        out.append(contentsOf: head)
        for _ in 0..<8 { out.append(contentsOf: oneChunk) }
        out.append(contentsOf: terminator)  // ONE terminator per body
    }
    return out
}

/// Run `body` `reps` times, return the MEDIAN duration.
func measure(_ reps: Int, _ body: () async throws -> Int) async rethrows -> Duration {
    var samples: [Duration] = []
    for i in 0..<(reps + 1) {
        let clock = ContinuousClock()
        let start = clock.now
        _ = try await body()
        if i > 0 { samples.append(clock.now - start) }  // first run = warmup
    }
    samples.sort()
    return samples[samples.count / 2]
}

func report(_ name: String, _ duration: Duration, items: Int, bytes: Int) {
    let ns = Double(duration.components.seconds) * 1e9
        + Double(duration.components.attoseconds) / 1e9
    let perItemUs = ns / Double(items) / 1000
    // bytes / ns × 1e9 = B/s; ÷ 1e6 = MB/s  ⇒  bytes/ns × 1e3.
    let mbps = Double(bytes) / ns * 1e3
    let padded = name.padding(toLength: 30, withPad: " ", startingAt: 0)
    let perItem = String(format: "%.2f", perItemUs)
        .padding(toLength: 12, withPad: " ", startingAt: 0)
    let rate = String(format: "%.1f", mbps)
    print("\(padded)\(perItem) µs/op  \(rate) MB/s")
}

// MARK: - Benchmarks

@main
struct Bench {
    static func main() async throws {
        print("http-codec bench (release build recommended)\n")
        // Pin the whole run to the bench executor — the production
        // shape (driveConnection runs on the loop Task, so actor
        // calls execute inline through
        // isSameExclusiveExecutionContext).
        try await Task(executorPreference: benchExecutor) {
            try await run()
        }.value
    }

    static func run() async throws {

        // 1. Head-only parsing (pipelined through one connection).
        let headCount = 20_000
        let headBytes = buildHeadStream(headCount)
        var parsed = 0
        let t1 = try await measure(5) {
            let conn = H1Conn<FeedIO>(
                io: FeedIO(headBytes),
                executor: benchExecutor.asUnownedSerialExecutor()
            )
            var n = 0
            while let head = try await conn.decodeHead() {
                if head.request.method != .GET { fatalError("bad parse") }
                n += 1
            }
            parsed = n
            return n
        }
        precondition(parsed == headCount)
        report("head parse (GET, 6 hdrs)", t1, items: headCount, bytes: headBytes.count)

        // 2. Content-Length bodies.
        let clCount = 5_000
        let clBody = 4 * 1024
        let clBytes = buildCLStream(clCount, bodySize: clBody)
        var clBodies = 0
        let t2 = try await measure(5) {
            let conn = H1Conn<FeedIO>(
                io: FeedIO(clBytes),
                executor: benchExecutor.asUnownedSerialExecutor()
            )
            var total = 0
            while let head = try await conn.decodeHead() {
                while let c = try await conn.nextBodyChunk(forGeneration: head.generation) {
                    total += c.count
                }
            }
            clBodies = total
            return total
        }
        precondition(clBodies == clCount * clBody)
        report("CL body (4 KiB POST)", t2, items: clCount, bytes: clBytes.count)

        // 3. Chunked bodies.
        let chCount = 5_000
        let chBytes = buildChunkedStream(chCount, bodySize: 4 * 1024)
        var chBodies = 0
        let t3 = try await measure(5) {
            let conn = H1Conn<FeedIO>(
                io: FeedIO(chBytes),
                executor: benchExecutor.asUnownedSerialExecutor()
            )
            var total = 0
            while let head = try await conn.decodeHead() {
                while let c = try await conn.nextBodyChunk(forGeneration: head.generation) {
                    total += c.count
                }
            }
            chBodies = total
            return total
        }
        precondition(chBodies == chCount * 4 * 1024)
        report("chunked body (4 KiB POST)", t3, items: chCount, bytes: chBytes.count)

        // 4. Response encoding.
        let encCount = 20_000
        let responseBody = [UInt8](repeating: 0x63, count: 512)
        var response = Response(status: .ok)
        response.headers.insert(.contentType, "application/json")
        response.headers.insert(.cacheControl, "max-age=60")
        response.headers.insert(HeaderName("x-request-id"), "0123456789abcdef")
        response.body = .buffered(responseBody)
        let encoder = H1Encoder()
        var buffer: [UInt8] = []
        buffer.reserveCapacity(2048)
        var encBytes = 0
        let t4 = try await measure(5) {
            var n = 0
            for _ in 0..<encCount {
                buffer.removeAll(keepingCapacity: true)
                let encoded = try encoder.encodeHead(
                    response, keepAlive: true, into: &buffer
                )
                if encoded != .buffered { fatalError("bad encode") }
                n += buffer.count + responseBody.count
            }
            encBytes = n
            return n
        }
        report("response encode (512 B body)", t4, items: encCount, bytes: encBytes)
    }
}
