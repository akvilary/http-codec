//===----------------------------------------------------------------------===//
//
//  ByteSearchTests.swift
//  HyperTests
//
//  Correctness tests for the SWAR byte-search primitives.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import Hyper

@Suite("SWAR ByteSearch")
struct ByteSearchTests {

    // MARK: - findByte

    @Test("findByte — needle present at start")
    func findByteAtStart() {
        let buf: [UInt8] = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49]
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findByte(0x41, in: ptr, from: 0, to: buf.count)
            #expect(result == 0)
        }
    }

    @Test("findByte — needle in middle (SWAR chunk)")
    func findByteInMiddle() {
        // 16 bytes — spans 2 SWAR chunks
        let buf: [UInt8] = Array("01234567ABCDEFGH".utf8)
        buf.withUnsafeBufferPointer { ptr in
            // 'D' is at index 11
            let result = ByteSearch.findByte(0x44, in: ptr, from: 0, to: buf.count)
            #expect(result == 11)
        }
    }

    @Test("findByte — needle in tail (< 8 bytes)")
    func findByteInTail() {
        let buf: [UInt8] = Array("0123".utf8)  // 4 bytes — below SWAR threshold
        buf.withUnsafeBufferPointer { ptr in
            // '2' (0x32) is at index 2 in "0123"
            let result = ByteSearch.findByte(0x32, in: ptr, from: 0, to: buf.count)
            #expect(result == 2)
        }
    }

    @Test("findByte — needle absent")
    func findByteAbsent() {
        let buf: [UInt8] = Array("0123456789abcdef".utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findByte(0x5A, in: ptr, from: 0, to: buf.count)  // 'Z'
            #expect(result == nil)
        }
    }

    @Test("findByte — first match wins when multiple present")
    func findByteFirstMatch() {
        // 'A' appears at indices 0, 5, 10
        let buf: [UInt8] = Array("A2345A2345A2345".utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findByte(0x41, in: ptr, from: 0, to: buf.count)
            #expect(result == 0)
        }
    }

    @Test("findByte — pattern in every byte (worst case)")
    func findByteAllMatch() {
        // All bytes are 0x41 ('A') — every SWAR iteration hits all 8
        let buf = [UInt8](repeating: 0x41, count: 32)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findByte(0x41, in: ptr, from: 0, to: buf.count)
            #expect(result == 0)
        }
    }

    // MARK: - findCRLFCRLF

    @Test("findCRLFCRLF — at start")
    func crlfcrlfStart() {
        let buf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A, 0x58]  // \r\n\r\n + 'X'
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findCRLFCRLF(in: ptr, from: 0, to: buf.count)
            #expect(result == 4)
        }
    }

    @Test("findCRLFCRLF — typical HTTP header end")
    func crlfcrlfTypical() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"
        let buf = Array(raw.utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findCRLFCRLF(in: ptr, from: 0, to: buf.count)
            // Layout: "GET / HTTP/1.1" (14) + "\r\n" (2) + "Host: x" (7) + "\r\n\r\n" (4) = 27
            // Returns position + 4 = 23 + 4 = 27
            #expect(result == 27)
        }
    }

    @Test("findCRLFCRLF — false positive \r alone")
    func crlfcrlfFalsePositive() {
        // Single \r at index 5, but not followed by \n\r\n
        let buf: [UInt8] = Array("abcde\rxyz".utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findCRLFCRLF(in: ptr, from: 0, to: buf.count)
            #expect(result == nil)
        }
    }

    @Test("findCRLFCRLF — absent")
    func crlfcrlfAbsent() {
        let buf: [UInt8] = Array("no terminator here".utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findCRLFCRLF(in: ptr, from: 0, to: buf.count)
            #expect(result == nil)
        }
    }

    // MARK: - findCRLF

    @Test("findCRLF — first line end")
    func crlfFirstLine() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\n"
        let buf = Array(raw.utf8)
        buf.withUnsafeBufferPointer { ptr in
            let result = ByteSearch.findCRLF(in: ptr, from: 0, to: buf.count)
            // Position of '\r' at index 14
            #expect(result == 14)
        }
    }
}
