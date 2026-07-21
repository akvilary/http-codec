Hyper — Swift port of the Rust `hyper` crate
===============================================

HTTP/1.1 (and eventually HTTP/2) connection codec + server runtime.
Direct 1:1 port of [**hyper** (Rust)](https://hyper.rs):

- `Conn<Io, T>` — per-connection driver (state machine over read/parse/encode/write)
- `Dispatcher` — drives the Conn through the request/response cycle
- `Decoder` — incremental HTTP/1.1 request parser (port of `httparse`)
- `Encoder` — HTTP/1.1 response writer (zero-interpolation status lines)
- `Body`, `Frame` — body model (port of `http_body` + hyper::body)
- `rt::{Read, Write, Timer}` — async I/O trait abstraction (port of hyper::rt)
- `server::conn::http1::Builder` — high-level HTTP/1 server connection setup

Built on top of [`http`](https://github.com/akvilary/http) (the Swift port
of the `http` crate), exactly as Rust's hyper depends on the `http` crate.

## Status

Early / in development. Currently used by:

- [`starlight`](https://github.com/akvilary/starlight) — Swift port of axum.

## Platform

Linux primary (epoll via mio). All sources compile on macOS via Swift
Concurrency's global executor.

## Installation

```swift
.package(url: "https://github.com/akvilary/hyper.git", from: "0.1.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "Hyper", package: "hyper"),
])
```

## Layout

Mirrors hyper's `src/` tree 1:1:

```
Sources/Hyper/
├── Hyper.swift              lib.rs
├── Error.swift              error.rs
├── Body/                    body/
├── Common/                  common/
├── Ext/                     ext/
├── Headers.swift            headers.rs
├── Proto/                   proto/
│   └── H1/                  proto/h1/
│       ├── Conn.swift       conn.rs
│       ├── Decoder.swift    decode.rs (port of httparse)
│       ├── Dispatcher.swift dispatch.rs
│       ├── Encoder.swift    encode.rs
│       ├── IO.swift         io.rs (Buffered<Io>)
│       └── Server.swift     role.rs (server side)
├── RT/                      rt/ (Read/Write/Timer)
├── Server/                  server/
│   └── Conn/                server/conn/
│       └── HTTP1.swift      http1.rs
└── Service/                 service/
```

## License

MIT — see [LICENSE](LICENSE).
