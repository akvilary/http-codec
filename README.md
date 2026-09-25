# HTTPCodec

A Swift port of [**hyper** (Rust)](https://hyper.rs): the HTTP/1.1
connection **codec** — request parsing, response encoding, the
connection state machine, the body model, and the runtime I/O
abstraction. The same role the `hyper` crate plays in the Rust
axum/hyper/tower ecosystem.

> **What this is — and isn't.** HTTPCodec is the **codec layer only**.
> It knows how to parse a request head, frame a body, and encode a
> response, but it does **not** bind a socket, run an event loop, or
> drive the request/response cycle — that lives in a server crate. In
> the Starlight workspace, [`starlight`](https://github.com/akvilary/starlight)
> supplies the runtime (`PollEventLoopIO` over a pulsar channel) and
> drives this codec from its `Worker`. This mirrors hyper, where
> `hyper::proto::h1::Conn` is runtime-agnostic and tokio integration
> sits one layer up.

## Status

Early / in development. Currently used by:

- [`starlight`](https://github.com/akvilary/starlight) — Swift port of axum.

## Platform

Linux primary (the runtime binding in StarlightServer uses epoll via
[`mio`](https://github.com/akvilary/mio)). The codec itself compiles on
macOS — it has no syscall dependencies.

## Installation

```swift
.package(url: "https://github.com/akvilary/http-codec.git", from: "0.2.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "HTTPCodec", package: "http-codec"),
])
```

Built on [`http`](https://github.com/akvilary/http) (the Swift port of
the `http` crate) for `Request` / `Response` / `HeaderMap` / `Method` /
`StatusCode` / `Uri` / `Version` / `Extensions`, exactly as Rust's hyper
depends on the `http` crate.

## Overview

### `H1Conn<IO>` — the connection state machine

Direct port of `hyper::proto::h1::Conn`. One instance per TCP
connection, amortised across keep-alive requests. `decodeHead()` parses
a request head lazily; the body is pulled on demand:

```swift
import HTTPCodec
import HTTP

// IO is supplied by the runtime (see Http1ConnectionIO below).
let conn = H1Conn(io: io, executor: executor)

let head = try await conn.decodeHead()      // DecodedHead? (nil = clean EOF)
let body = try await conn.nextBodyChunk(forGeneration: head.generation)  // [UInt8]?
try await conn.drainBody()                  // discard any unread body
```

The full request-smuggling defence suite lives here (regression targets
A17–A28): bare CR/LF in header values, `Content-Length` +
`Transfer-Encoding` conflict, conflicting `Content-Length`, missing
`Host`, malformed chunk framing, header/count bombs. A `generation`
counter makes stale body reads (from a handler that escaped its
`Request`) throw instead of corrupting the next keep-alive request.

### `Http1ConnectionIO` — runtime I/O (port of `hyper::rt`)

The codec never touches a file descriptor, epoll, or an event loop. It
asks the runtime through this protocol — the Swift analogue of hyper's
`rt::Read` / `rt::Write`:

```swift
public protocol Http1ConnectionIO: Sendable {
    func read(deadline: ContinuousClock.Instant?) async -> Int       // >0 / 0 EOF / <0 err
    func readView(count: Int) -> UnsafeBufferPointer<UInt8>          // borrow until next read
    func writeRaw(_ bytes: [UInt8]) -> Int                           // sync (interim 1xx)
}
```

Any runtime can drive the codec by implementing this — in StarlightServer
that's `PollEventLoopIO` over a pulsar `PollEventLoop`.

### Encoding & policy

- `H1Encoder` / `EncodedHead` — HTTP/1.1 response writer (zero-interpolation status lines, `writev`-friendly header/body split).
- `ServerTransaction` — server-side `Http1Transaction` policy (when to send `Connection: close`, body suppression for `204`/`304`, keep-alive decision).

### Body & primitives

- `HTTPCodecBody` / `Frame` — body model (port of `http_body` + `hyper::body`).
- `ByteSearch` — SWAR byte search (`\r\n\r\n`, single byte) — the Swift equivalent of `httparse`'s vectorised scanners.
- `AsyncTimer` — runtime timer abstraction (`hyper::rt::Timer`).

## Layout

```
Sources/HTTPCodec/
├── HTTPCodec.swift              module prelude (@_exported import HTTP)
├── Error.swift                  HTTPCodecError
├── Body/
│   └── Body.swift               HTTPCodecBody, Frame
├── Proto/H1/                    HTTP/1.1 wire codec
│   ├── H1Conn.swift             H1Conn<IO> + H1ConnError + DecodedHead  (hyper proto::h1::Conn)
│   ├── Http1ConnectionIO.swift  runtime I/O protocol                   (hyper rt::Read/Write)
│   ├── Encoder.swift            H1Encoder, EncodedHead                  (hyper proto::h1::encode)
│   ├── Server.swift             ServerTransaction (keep-alive policy)   (hyper proto::h1::Server)
│   └── ByteSearch.swift         SWAR scanners                           (httparse helpers)
└── RT/
    └── Timer.swift              AsyncTimer                              (hyper rt::Timer)
```

## Why a separate package?

The codec is reusable across runtimes (any `Http1ConnectionIO` impl) and
across servers — exactly why hyper ships `proto::h1::Conn` in the hyper
crate rather than folding it into a server. Keeping it here lets a
future non-Starlight server (or a client) share the same codec without
pulling in pulsar or the axum-style router.

## License

MIT — see [LICENSE](LICENSE).
