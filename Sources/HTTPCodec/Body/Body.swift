//===----------------------------------------------------------------------===//
//
//  Body.swift / Frame.swift
//  HTTPCodec/Body
//
//  Port of `hyper::body` + `http_body::Body`. The body model that
//  flows through the codec: streaming-capable, frame-oriented.
//
//  Rust splits this across two crates:
//    - `http_body::Body` trait — `poll_frame` returns `Frame<Data>`
//    - `hyper::body::Body` concrete struct — wraps the trait object
//
//  We collapse both into one enum-with-associated-values: a Hyper.Body
//  is either `.empty`, `.buffered([UInt8])`, or `.stream(AsyncSequence)`.
//  Consumers match on the enum and process accordingly.
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTP

/// A single frame in a body stream. Port of `http_body::Frame<T>`.
public enum Frame<Data: Sendable>: Sendable {
    /// Body data chunk.
    case data(Data)
    /// Optional trailers — sent after the final data frame.
    case trailers(HeaderMap)
}

/// Concrete body type used throughout hyper. Combines:
///
/// - `.empty` — no body (HEAD response, GET request without body).
/// - `.buffered` — full body in memory, ready to read once.
/// - `.stream` — chunks delivered over time via an `AsyncSequence`.
///
/// Mirrors `hyper::body::Body` (which itself wraps an internal enum
/// over `Incoming`, `Sender`-channel, and concrete impls).
public enum HTTPCodecBody: Sendable {
    case empty
    case buffered([UInt8])
    case stream(any AsyncSequence<[UInt8], Error> & Sendable)

    /// `true` if this body has no bytes to deliver.
    public var isEmpty: Bool {
        switch self {
        case .empty: return true
        case .buffered(let b): return b.isEmpty
        case .stream: return false
        }
    }
}
