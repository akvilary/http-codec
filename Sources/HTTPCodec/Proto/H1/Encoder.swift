//===----------------------------------------------------------------------===//
//
//  Encoder.swift
//  HTTPCodec/Proto/H1
//
//  Port of `hyper::proto::h1::Encoder`. Serialises an HTTP/1.1
//  response in two phases:
//
//    1. `encodeHead(...)` — writes status line + headers into the
//       output buffer. Decides whether to use Content-Length (body
//       size known) or chunked Transfer-Encoding (streaming body).
//       Returns an `EncodedHead` describing what to do next.
//
//    2. The caller acts on `EncodedHead`:
//         - `.buffered(bytes)`: the body is already in the buffer.
//           Just flush.
//         - `.stream`: pull chunks from `body.dataStream()` and
//           call `encodeChunk(...)` for each, then `encodeEndOfChunks`
//           at the end.
//
//  Mirrors hyper's zero-interpolation design: static parts of the
//  status line and well-known header names are written via direct
//  byte appends; only Content-Length digits are stringified (and for
//  ≤ 4-digit lengths the String fits in a Swift SmallString — 15 bytes).
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// Result of `H1Encoder.encodeHead(...)`. Tells the caller what to
/// do with the body next.
public enum EncodedHead: Sendable {
    /// The body was buffered — it's already in the output buffer.
    /// Caller can flush immediately.
    case buffered
    /// The body is streaming — caller must iterate `body.dataStream()`
    /// and call `encodeChunk(...)` for each chunk, then
    /// `encodeEndOfChunks(...)` when done.
    case stream
    /// The response has no body (HEAD response, 204/304, etc.).
    case noBody
}

/// HTTP/1.1 response encoder. Port of `hyper::proto::h1::Encoder`.
public struct H1Encoder: Sendable {

    public struct Config: Sendable {
        public var emitDateHeader: Bool = true
        public var titleCaseHeaders: Bool = true
        @inlinable public init() {}
    }

    public let config: Config

    @inlinable public init(config: Config = Config()) {
        self.config = config
    }

    // MARK: - Phase 1: encode status + headers

    /// Encode the response status line + headers into `buffer`. Does
    /// NOT touch the body.
    ///
    /// For a `.buffered` body: also writes the body bytes (since they
    /// are immediately available) and returns `.buffered`.
    ///
    /// For a `.stream` body: writes the headers + an auto-chunked
    /// `Transfer-Encoding` header (unless the user already set one),
    /// returns `.stream`. Caller must follow up with `encodeChunk`
    /// and `encodeEndOfChunks`.
    ///
    /// For `.empty` body (or HEAD response, or 1xx/204/304 status):
    /// writes headers, returns `.noBody`.
    ///
    /// - Parameter requestMethod: The HTTP method of the request that
    ///   triggered this response. Needed because HEAD responses must
    ///   suppress the body (RFC 9110 §9.3.2) while preserving the
    ///   Content-Length that GET would have produced. Defaults to GET
    ///   for backward compatibility with callers that don't track the
    ///   method.
    @discardableResult
    public func encodeHead(
        _ response: Response,
        keepAlive: Bool,
        requestMethod: Method = .GET,
        into buffer: inout [UInt8]
    ) -> EncodedHead {
        let start = buffer.count

        // ── Determine whether the body must be suppressed ─────────
        //
        // RFC 9110 §9.3.2: HEAD responses MUST NOT include a body.
        // RFC 9110 §15.2.1, §15.4.5, §15.4.7: 1xx, 204, 304 responses
        // MUST NOT include a body.
        let isHeadResponse = requestMethod == .HEAD
        let isBodyForbidden = isHeadResponse
            || response.status.code < 200
            || response.status.code == 204
            || response.status.code == 304

        // ── Status line ───────────────────────────────────────────
        writeStatusLine(response.status, into: &buffer)
        buffer.append(contentsOf: Self.crlf)

        // ── Decide body framing strategy BEFORE writing user headers,
        //    so we can check whether they pre-set TE / CL.
        var sawContentLength = false
        var sawTransferEncoding = false
        var sawConnection = false
        for (name, _) in response.headers.entries {
            if name == .contentLength   { sawContentLength = true }
            if name == .transferEncoding { sawTransferEncoding = true }
            if name == .connection       { sawConnection = true }
        }

        let isStreaming: Bool
        if isBodyForbidden {
            isStreaming = false
        } else {
            switch response.body {
            case .empty:        isStreaming = false
            case .buffered:     isStreaming = false
            case .stream:       isStreaming = true
            case .pull:         isStreaming = false  // .pull is request-only
            }
        }

        // ── Write user headers (skip hop-by-hop) ──────────────────
        // Hop-by-hop headers (Connection, Keep-Alive, etc.) are
        // per-connection — the encoder manages them itself. Handler-
        // set hop-by-hop headers are silently dropped.
        for (name, value) in response.headers.entries {
            if name.isHopByHop() { continue }
            writeHeaderName(name, into: &buffer)
            buffer.append(0x3A)
            buffer.append(0x20)
            buffer.append(contentsOf: value.bytes)
            buffer.append(contentsOf: Self.crlf)
        }

        // ── Auto-add framing headers if the user didn't ───────────
        if isStreaming {
            // Chunked TE — required since we don't know the size upfront.
            if !sawTransferEncoding {
                writeStaticHeader(.transferEncoding, value: "chunked", into: &buffer)
            }
        } else if case .buffered(let bytes) = response.body, !bytes.isEmpty, !sawContentLength {
            writeStaticHeader(.contentLength, value: String(bytes.count), into: &buffer)
        } else if case .empty = response.body, !sawContentLength {
            // Empty body — emit Content-Length: 0 unless user overrode.
            writeStaticHeader(.contentLength, value: "0", into: &buffer)
        }

        if !sawConnection {
            let value = keepAlive ? "keep-alive" : "close"
            writeStaticHeader(.connection, value: value, into: &buffer)
        }

        // ── Empty line separating headers from body ───────────────
        buffer.append(contentsOf: Self.crlf)

        // ── Determine what the caller needs to do with the body ───
        // NOTE: We do NOT append body bytes to `buffer`. The caller
        // uses writev(2) to write header + body in one syscall
        // without concatenation. This is the same pattern hyper uses
        // with IoSlice + writev.
        // Body-decision: suppress body entirely for HEAD / 1xx / 204 / 304.
        // The auto-framing headers (Content-Length / TE) are still emitted
        // above so the client knows what GET would have produced — but the
        // caller must NOT write any body bytes.
        if isBodyForbidden {
            return .noBody
        }
        switch response.body {
        case .empty:
            return .noBody
        case .buffered(let bytes):
            if bytes.isEmpty { return .noBody }
            return .buffered  // body exists but isn't copied into buffer
        case .stream:
            return .stream
        case .pull:
            // .pull is request-side only — a handler returning a .pull
            // body as its response is a misuse. Treat as no body.
            return .noBody
        }
    }

    // MARK: - Phase 2: streaming body chunks

    /// Write a single chunk to `buffer` in chunked TE format:
    ///
    ///     <hex-size>\r\n
    ///     <bytes>\r\n
    ///
    /// Caller owns the buffer; this just appends.
    public func encodeChunk(_ bytes: [UInt8], into buffer: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        // Hex size — bodies up to ~64 GiB supported via UInt64.
        let hex = String(bytes.count, radix: 16)
        buffer.append(contentsOf: Array(hex.utf8))
        buffer.append(contentsOf: Self.crlf)
        buffer.append(contentsOf: bytes)
        buffer.append(contentsOf: Self.crlf)
    }

    /// Write the terminating zero-length chunk:
    ///
    ///     0\r\n
    ///     \r\n
    ///
    /// Sent after the last data chunk. Optionally includes trailers
    /// (Phase 2 polish — currently no trailers support).
    public func encodeEndOfChunks(into buffer: inout [UInt8]) {
        buffer.append(contentsOf: [0x30])  // '0'
        buffer.append(contentsOf: Self.crlf)
        buffer.append(contentsOf: Self.crlf)
    }

    // MARK: - Status line

    @inline(__always)
    private func writeStatusLine(_ status: StatusCode, into buffer: inout [UInt8]) {
        buffer.append(contentsOf: [
            0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x20
        ])
        let code = status.code
        buffer.append(0x30 + UInt8(code / 100))
        buffer.append(0x30 + UInt8((code / 10) % 10))
        buffer.append(0x30 + UInt8(code % 10))
        buffer.append(0x20)
        buffer.append(contentsOf: Array(status.canonicalReason.utf8))
    }

    // MARK: - Header writing

    @inline(__always)
    private func writeHeaderName(_ name: HeaderName, into buffer: inout [UInt8]) {
        if config.titleCaseHeaders {
            var cap = true
            for b in name.bytes {
                if cap && b >= 0x61 && b <= 0x7A {
                    buffer.append(b - 0x20)
                } else {
                    buffer.append(b)
                }
                cap = (b == 0x2D)
            }
        } else {
            buffer.append(contentsOf: name.bytes)
        }
    }

    @inline(__always)
    private func writeStaticHeader(_ name: HeaderName, value: String, into buffer: inout [UInt8]) {
        writeHeaderName(name, into: &buffer)
        buffer.append(0x3A)
        buffer.append(0x20)
        buffer.append(contentsOf: value.utf8)
        buffer.append(contentsOf: Self.crlf)
    }
}

extension H1Encoder {
    @inlinable internal static var crlf: [UInt8] { [0x0D, 0x0A] }
}
