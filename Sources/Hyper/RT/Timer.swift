//===----------------------------------------------------------------------===//
//
//  Timer.swift
//  Hyper/RT
//
//  Port of `hyper::rt::Timer`. A sleep/wait abstraction the codec
//  uses for header/body timeouts.
//
//===----------------------------------------------------------------------===//

import Foundation

/// Sleep until `deadline` then resume. Port of `hyper::rt::Timer`.
///
/// Phase-1 skeleton: just `Task.trySuspend` + `DispatchSource`. A
/// more efficient impl uses timerfd on Linux (one timerfd per
/// PollEventLoop, registered as a watch channel).
public protocol AsyncTimer: Sendable {
    /// Sleep until the given deadline.
    func sleep(until deadline: ContinuousClock.Instant) async
}
