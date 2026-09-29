# HTTPCodec

A Swift port of [**hyper** (Rust)](https://hyper.rs): the HTTP/1.1
connection **codec** — request parsing, response encoding, the
connection state machine, and the runtime I/O abstraction. The same
role the `hyper` crate plays in the Rust axum/hyper/tower ecosystem.

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
.package(url: "https://github.com/akvilary/http-codec.git", from: "0.3.0")
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

The full request-smuggling defence suite lives here: bare CR/LF and
control bytes in header values, `Content-Length` +
`Transfer-Encoding` conflict, conflicting or non-digit
`Content-Length`, missing / multiple `Host`, `Transfer-Encoding` that
doesn't end in exactly one `chunked` codeword, obs-fold line folding,
control bytes in the method / request target, malformed chunk framing,
and header/count/line bombs (every scanner in the body path is
bounded — chunk-ext, chunk-size and trailer lines cannot grow the
buffer without limit; the size limit applies to complete heads too).
A `generation` counter makes stale body reads (from a handler that
escaped its `Request`) throw instead of corrupting the next keep-alive
request.

Hop-by-hop handling follows RFC 9110 §7.6.1: the standard set is
stripped and headers **named in `Connection`** are stripped too;
`Upgrade` stays visible to handlers (needed for WebSocket-style
handshakes, hyper parity). Chunked-body **trailers** are parsed,
validated (framing/hop-by-hop names dropped per RFC 9110 §6.5.1) and
exposed after the body ends via `conn.trailers(forGeneration:)` —
or, for handlers, through the `RequestTrailers` extension the
connection driver inserts into `request.extensions`.

**Error taxonomy** (for the server's status mapping):

| `H1ConnError` | server action |
|---|---|
| `.requestTooLarge` | 413 + close |
| `.timedOut` | close (or 408 on the head phase) |
| `.incompleteMessage`, `.ioError` | close silently |
| everything else (parse errors) | 400 + close |

Reads are bounded by a per-phase absolute deadline (header / body /
drain) passed to the runtime — a slow-drip client (Slowloris) is
bounded across the whole phase, and the incremental header scanner
keeps partial-head re-scans O(total) instead of O(n²).

### `Http1ConnectionIO` — runtime I/O (port of `hyper::rt`)

The codec never touches a file descriptor, epoll, or an event loop. It
asks the runtime through this protocol — the Swift analogue of hyper's
`rt::Read` / `rt::Write`:

```swift
public protocol Http1ConnectionIO: Sendable {
    func read(deadline: ContinuousClock.Instant?) async -> Int  // >0 / 0 EOF / -1 err / -2 timeout
    func readView(count: Int) -> UnsafeBufferPointer<UInt8>     // borrow until next read
    func writeRaw(_ bytes: [UInt8]) -> Int                      // sync (interim 1xx)
}
```

Any runtime can drive the codec by implementing this — in StarlightServer
that's `PollEventLoopIO` over a pulsar `PollEventLoop`.

### Encoding & policy

- `H1Encoder` / `EncodedHead` — HTTP/1.1 response writer (zero-interpolation
  status lines, `writev`-friendly header/body split, cached `Date`
  header, validated output: response splitting via CRLF in a header is
  impossible — it throws `H1EncodeError` instead of reaching the wire).
  Framing is derived from the actual body: `.buffered` → `writev` with
  `Content-Length`, `.stream` → chunked, `.streamIdentity(length:)` →
  raw bytes delimited by a user-supplied `Content-Length` (the driver
  aborts on over-/under-delivery). 1xx/204 never carry framing headers;
  HEAD preserves the length GET would have produced. `Upgrade` is
  forwarded (101 Switching Protocols handshakes).
- `ServerTransaction` — server-side keep-alive policy
  (`shouldKeepAlive(requestKeepAlive:response:explicitConnection:)`:
  the request side dominates, the response can only veto with an
  explicit boundary-aware `close` token — this is what keeps
  HTTP/1.0 + `Connection: keep-alive` alive through a silent
  response).

### Primitives

- `ByteSearch` — SWAR byte search (`\r\n\r\n`, `\r\n`, single byte) —
  the Swift equivalent of `httparse`'s vectorised scanners.

## Layout

```
Sources/HTTPCodec/
├── HTTPCodec.swift              module prelude (@_exported import HTTP)
└── Proto/H1/                    HTTP/1.1 wire codec
    ├── H1Conn.swift             H1Conn<IO> + H1ConnError + DecodedHead  (hyper proto::h1::Conn)
    ├── Http1ConnectionIO.swift  runtime I/O protocol                   (hyper rt::Read/Write)
    ├── Encoder.swift            H1Encoder, EncodedHead, H1EncodeError   (hyper proto::h1::encode)
    ├── Server.swift             ServerTransaction (keep-alive policy)   (hyper proto::h1::Server)
    └── ByteSearch.swift         SWAR scanners                           (httparse helpers)
```

## Why a separate package?

The codec is reusable across runtimes (any `Http1ConnectionIO` impl) and
across servers — exactly why hyper ships `proto::h1::Conn` in the hyper
crate rather than folding it into a server. Keeping it here lets a
future non-Starlight server (or a client) share the same codec without
pulling in pulsar or the axum-style router.

## License

MIT — see [LICENSE](LICENSE).
