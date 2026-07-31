// swift-tools-version: 6.2
//
//  Hyper — Swift port of the Rust `hyper` crate.
//
//  HTTP/1.1 (and eventually HTTP/2) connection codec + server runtime.
//  Direct 1:1 port of https://docs.rs/hyper — same Conn / Dispatcher /
//  Encoder / Decoder split, same Body model, same rt (Read/Write/Timer)
//  trait abstraction.
//
//  Depends on the Swift port of the `http` crate
//  (https://github.com/akvilary/http) for message types, exactly as
//  Rust's hyper depends on the `http` crate.
//
//  Layout (mirrors hyper's src/ tree):
//
//    Sources/Hyper/
//    ├── Hyper.swift              lib.rs — prelude / re-exports
//    ├── Error.swift              error.rs
//    ├── Body/                    body/  — Body, Frame, Incoming
//    ├── Common/                  common/ — small utilities
//    ├── Ext/                     ext/    — request/response extensions
//    ├── Headers.swift            headers.rs — header parsing helpers
//    ├── Proto/                   proto/  — wire-level codec
//    │   └── H1/                  proto/h1/ — HTTP/1.1
//    │       ├── Conn.swift       Conn<Io, T> — connection driver
//    │       ├── Decoder.swift    request parser (port of httparse)
//    │       ├── Dispatcher.swift read/parse/dispatch/write loop
//    │       ├── Encoder.swift    response writer
//    │       ├── IO.swift         Buffered<Io> wrapper
//    │       └── Server.swift     server-side Http1Transaction impl
//    ├── RT/                      rt/ — Read / Write / Timer traits
//    ├── Server/                  server/
//    │   └── Conn/                server/conn/
//    │       └── HTTP1.swift      server/conn/http1.rs — high-level builder
//    └── Service/                 service/ — tower-Service adapters
//
import PackageDescription

let package = Package(
    name: "http-codec",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(name: "HTTPCodec", targets: ["HTTPCodec"]),
    ],
    dependencies: [
        // Swift port of the `http` crate — Request/Response/Method/
        // StatusCode/HeaderMap/Uri/Version.
        .package(path: "../http"),
    ],
    targets: [
        .target(
            name: "HTTPCodec",
            dependencies: [
                .product(name: "HTTP", package: "http"),
            ],
            path: "Sources/HTTPCodec",
            swiftSettings: baseSwiftSettings
        ),
        .testTarget(
            name: "HTTPCodecTests",
            dependencies: ["HTTPCodec"],
            path: "Tests/HTTPCodecTests",
            swiftSettings: baseSwiftSettings
        ),
    ]
)

var baseSwiftSettings: [SwiftSetting] {
    [
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("StrictMemorySafety"),
    ]
}
