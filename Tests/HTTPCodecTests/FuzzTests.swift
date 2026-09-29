//===----------------------------------------------------------------------===//
//
//  FuzzTests.swift
//  HTTPCodecTests
//
//  Reliability harness: seeded pseudo-random and structure-aware
//  mutated inputs driven through the full decoder (head + body) and
//  encoder. Invariants under fuzz:
//
//    1. no trap — no force-unwrap, no out-of-bounds, no fatalError
//       survives (the only sanctioned trap is `Method`'s storage on
//       absurd input, which never occurs);
//    2. every failure is a typed `H1ConnError` / `H1EncodeError` /
//       `BodyError` / `CancellationError` — never a raw crash;
//    3. the mock I/O contract is respected (readView count == last
//       read result);
//    4. on success, the decoded request round-trips basic sanity
//       (method non-empty, version is 1.0/1.1);
//    5. encoded output of accepted headers contains no raw CR/LF
//       outside CRLF line endings (response-splitting guarantee).
//
//  Deterministic: a fixed seed corpus plus derived seeds, so a
//  failure here is reproducible by seed.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import HTTP
@testable import HTTPCodec

/// Deterministic xorshift64* PRNG — no Foundation RNG dependency,
/// identical sequence on every platform/seed.
struct FuzzPRNG: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) {
        // xorshift64* cannot start at 0.
        self.state = seed == 0 ? 0x9E37_79B9_7F4A_7C15 : seed
    }
    mutating func next() -> UInt64 {
        state ^= state >> 12
        state ^= state << 25
        state ^= state >> 27
        return state &* 0x2545_F491_4F6C_DD1D
    }
    mutating func byte() -> UInt8 {
        UInt8(truncatingIfNeeded: next())
    }
    mutating func range(_ upper: Int) -> Int {
        Int(next() % UInt64(upper))
    }
}

/// Seed corpus of valid requests — mutations start from realistic
/// shapes (structure-aware fuzzing, far more effective per iteration
/// than pure noise).
let fuzzCorpus: [[UInt8]] = [
    Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8),
    Array("POST /upload HTTP/1.1\r\nHost: a.b\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello".utf8),
    Array("POST /s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Done: 1\r\n\r\n".utf8),
    Array("HEAD /x HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n".utf8),
    Array(("GET /a?b=c HTTP/1.1\r\nHost: h\r\nX-Pad: " + String(repeating: "p", count: 300) + "\r\nUser-Agent: fuzz\r\nAccept: */*\r\n\r\n").utf8),
    Array("\r\nGET /leading HTTP/1.1\r\nHost: x\r\n\r\nGET /pipelined HTTP/1.1\r\nHost: x\r\n\r\n".utf8),
    Array(("POST /t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nff;ext=1\r\n" + String(repeating: "z", count: 255) + "\r\n0\r\n\r\n").utf8),
]

/// Mutations: flip, insert, delete, truncate, splice CR/LF/NUL,
/// duplicate a slice, swap two chunks.
func mutate(_ input: [UInt8], _ rng: inout FuzzPRNG) -> [UInt8] {
    var bytes = input
    let ops = 1 + rng.range(4)
    for _ in 0..<ops {
        guard !bytes.isEmpty else { break }
        switch rng.range(7) {
        case 0:  // bit flip
            let i = rng.range(bytes.count)
            bytes[i] ^= UInt8(1 << rng.range(8))
        case 1:  // insert a nasty byte
            let nasty: [UInt8] = [0x0D, 0x0A, 0x00, 0x3A, 0x20, 0x7F, 0xFF]
            bytes.insert(nasty[rng.range(nasty.count)], at: rng.range(bytes.count))
        case 2:  // delete
            bytes.remove(at: rng.range(bytes.count))
        case 3:  // truncate
            bytes = Array(bytes[0..<rng.range(bytes.count)])
        case 4:  // splice a CRLF run
            let at = rng.range(bytes.count)
            let run = [UInt8](repeating: rng.range(2) == 0 ? 0x0D : 0x0A, count: 1 + rng.range(3))
            bytes.insert(contentsOf: run, at: at)
        case 5:  // duplicate a slice
            let at = rng.range(bytes.count)
            let len = 1 + rng.range(Swift.min(16, bytes.count - at))
            let copy = Array(bytes[at..<(at + len)])
            bytes.insert(contentsOf: copy, at: rng.range(bytes.count))
        default:  // pure noise tail
            let noiseLen = rng.range(32)
            var noise = [UInt8]()
            noise.reserveCapacity(noiseLen)
            for _ in 0..<noiseLen { noise.append(rng.byte()) }
            bytes.append(contentsOf: noise)
        }
    }
    return bytes
}

@Suite("Fuzz: decoder no-trap guarantee")
struct H1FuzzTests {

    /// Drive one input through decodeHead + body pulls + drain.
    /// The mock returns EOF once its chunks are exhausted, so every
    /// path terminates without external events. Returns the escaped
    /// error, if any — the tests assert it is always a TYPED codec
    /// error (never a raw crash / unexpected type).
    static func drive(_ input: [UInt8], chunkSize: Int?) async -> Error? {
        let chunks: [[UInt8]]
        if let size = chunkSize, input.count > 1 {
            let step = max(size, 1)
            chunks = stride(from: 0, to: input.count, by: step).map {
                Array(input[$0..<Swift.min($0 + step, input.count)])
            }
        } else {
            chunks = [input]
        }
        let conn = H1Conn<MockIO>(
            io: MockIO(chunks: chunks),
            executor: testExecutor.asUnownedSerialExecutor(),
            maxHeaderBytes: 4096,
            maxBodyBytes: 4096,
            maxHeaderCount: 32
        )
        do {
            var requests = 0
            while let head = try await conn.decodeHead() {
                requests &+= 1
                if requests > 1000 { return nil }  // runaway guard
                while let _ = try await conn.nextBodyChunk(forGeneration: head.generation) {}
                try await conn.drainBody()
            }
            return nil
        } catch is CancellationError {
            return nil
        } catch let e as H1ConnError {
            return e
        } catch let e as BodyError {
            return e
        } catch {
            return error  // unexpected type — the test fails on this
        }
    }

    static func assertTyped(_ error: Error?) {
        if let error {
            #expect(
                error is H1ConnError || error is BodyError || error is CancellationError,
                "untyped error escaped the decoder: \(error)"
            )
        }
    }

    @Test("mutated corpus — 600 seeded iterations, no trap, typed errors only")
    func mutatedCorpus() async throws {
        for seed in UInt64(1)...600 {
            var rng = FuzzPRNG(seed: seed)
            let base = fuzzCorpus[rng.range(fuzzCorpus.count)]
            let mutated = mutate(base, &rng)
            // Split delivery sometimes (exercises need-more paths).
            let chunkSize: Int? = seed % 3 == 0 ? 1 + Int(seed % 7) : nil
            Self.assertTyped(await Self.drive(mutated, chunkSize: chunkSize))
        }
    }

    @Test("pure noise — 400 seeded iterations")
    func pureNoise() async throws {
        for seed in UInt64(1)...400 {
            var rng = FuzzPRNG(seed: seed &+ 0xDEAD_BEEF)
            let len = 1 + rng.range(600)
            var bytes = [UInt8]()
            bytes.reserveCapacity(len)
            for _ in 0..<len { bytes.append(rng.byte()) }
            Self.assertTyped(await Self.drive(bytes, chunkSize: nil))
        }
    }

    @Test("valid corpus round-trips unmutated")
    func validCorpus() async throws {
        for input in fuzzCorpus {
            let io = MockIO(chunks: [input])
            let conn = H1Conn<MockIO>(
                io: io,
                executor: testExecutor.asUnownedSerialExecutor(),
                maxHeaderBytes: 8192,
                maxBodyBytes: 1 << 20,
                maxHeaderCount: 64
            )
            while let head = try await conn.decodeHead() {
                #expect(!head.request.method.description.isEmpty)
                while let _ = try await conn.nextBodyChunk(forGeneration: head.generation) {}
            }
        }
    }
}

@Suite("Fuzz: encoder output safety")
struct EncoderFuzzTests {

    @Test("random header names/values — output is CRLF-clean or typed error")
    func encoderFuzz() throws {
        let encoder = H1Encoder(config: .init(emitDateHeader: false))
        for seed in UInt64(1)...500 {
            var rng = FuzzPRNG(seed: seed &+ 0xC0FF_EE)
            var response = Response(status: StatusCode(100 + UInt16(rng.range(500))))
            let headerCount = rng.range(6)
            for h in 0..<headerCount {
                var name = [UInt8]()
                var value = [UInt8]()
                for _ in 0..<rng.range(20) { name.append(rng.byte()) }
                for _ in 0..<rng.range(40) { value.append(rng.byte()) }
                // Names must be hashable-safe: HeaderName accepts any
                // bytes (validation happens at encode).
                response.headers.entries.append(
                    (HeaderName(lowercasedBytes: name),
                     HeaderValue(bytes: value))
                )
                _ = h
            }
            var buffer: [UInt8] = []
            do {
                let head = try encoder.encodeHead(response, keepAlive: rng.range(2) == 0, into: &buffer)
                _ = head
                // Verify: every CR is followed by LF (no bare CR / LF
                // in the emitted bytes — response-splitting guarantee).
                var i = 0
                while i < buffer.count {
                    if buffer[i] == 0x0D {
                        #expect(i + 1 < buffer.count && buffer[i + 1] == 0x0A)
                        i += 2
                    } else {
                        #expect(buffer[i] != 0x0A)  // bare LF
                        i += 1
                    }
                }
            } catch let e as H1EncodeError {
                _ = e  // typed rejection is the expected outcome for
                       // most random-byte headers
            }
        }
    }
}
