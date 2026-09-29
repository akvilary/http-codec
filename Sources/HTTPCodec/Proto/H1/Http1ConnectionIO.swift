//===----------------------------------------------------------------------===//
//
//  Http1ConnectionIO.swift
//  HTTPCodec/Proto/H1
//
//  The I/O surface a runtime must supply to drive an HTTP/1.1 codec
//  connection. Direct port of hyper's `rt::Read` / `rt::Write` split:
//  the codec (`Conn`, `Decoder`, body framing) stays runtime-agnostic;
//  the runtime implements this protocol and hands it to the codec.
//
//  In the Starlight workspace, `PollEventLoopIO` (in StarlightServer)
//  adapts this to a pulsar `PollEventLoop` channel — the analogue of
//  hyper's tokio integration supplying `hyper::rt::Read/Write` over a
//  tokio I/O handle.
//
//===----------------------------------------------------------------------===//

import Foundation

/// Runtime-supplied I/O for an HTTP/1.1 codec connection.
///
/// The codec never touches a file descriptor, epoll, or an event loop
/// directly — it asks the runtime through this protocol. This keeps the
/// codec reusable across runtimes (any `Http1ConnectionIO` impl) and is
/// what lets `hyper::proto::h1::Conn` live in `hyper` rather than in a
/// server crate.
///
/// **Threading**: all three methods are invoked from the codec's
/// executor thread (the connection's loop thread). The runtime may rely
/// on that — e.g. pulsar's `getReadView` is only valid on the loop
/// thread.
public protocol Http1ConnectionIO: Sendable {

    /// Read into the runtime's internal per-channel buffer; return the
    /// number of bytes made available.
    ///
    /// - Returns: `> 0` bytes read, `0` for a clean EOF (peer closed),
    ///   `-1` for an I/O error or cancellation (including loop
    ///   teardown — `ECANCELED`), `-2` for the phase deadline elapsing
    ///   (timeout). The codec distinguishes all four outcomes:
    ///   `0` mid-message → `incompleteMessage`, `-1` → `ioError`,
    ///   `-2` → `timedOut`.
    ///
    /// - Parameter deadline: absolute time after which an unanswered
    ///   read is failed with `-2`. `nil` disables the bound. The codec
    ///   passes a per-phase deadline (header / body / drain) so a
    ///   slow-drip client (Slowloris) is bounded across the whole
    ///   phase, not just per individual `read(2)`.
    func read(deadline: ContinuousClock.Instant?) async -> Int

    /// Borrow the first `count` bytes produced by the most recent
    /// `read(deadline:)`.
    ///
    /// - Important: the returned pointer is valid **only** until the
    ///   next `read(deadline:)` on this I/O handle (the runtime may
    ///   reuse or replace its buffer) and **only** on the codec's
    ///   executor thread. Callers must copy the bytes out before
    ///   another read — the H1 codec does this immediately in
    ///   `appendReadView`.
    func readView(count: Int) -> UnsafeBufferPointer<UInt8>

    /// Write raw bytes synchronously. Used for tiny interim responses
    /// (e.g. `100 Continue`) that must go out before the request body
    /// is read.
    ///
    /// - Returns: bytes written (`0...bytes.count`), or `< 0` on
    ///   error. A **partial** write (`0 < n < bytes.count`, e.g. the
    ///   socket buffer filled mid-write on a non-blocking fd) is
    ///   reported as-is: the codec treats any result `< bytes.count`
    ///   as fatal for the connection — the interim response would be
    ///   truncated on the wire and the peer left waiting — and tears
    ///   the connection down.
    ///
    /// Synchronous (not `async`) by design: the codec is already on its
    /// loop thread and the payload is minute (~27 bytes), so the cost
    ///   of a readiness wait is not justified — same trade-off hyper
    ///   makes for interim `1xx` writes.
    func writeRaw(_ bytes: [UInt8]) -> Int
}
