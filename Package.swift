// swift-tools-version: 6.2
//
//  HTTPCodec — Swift port of the Rust `hyper` crate (codec layer).
//
//  HTTP/1.1 connection codec: request parsing, response encoding, the
//  connection state machine, the body model, and a runtime-agnostic
//  I/O abstraction. Direct port of https://docs.rs/hyper — same
//  Conn / Encoder / Body / rt split, but the runtime binding (socket,
//  event loop, request/response cycle) lives in a server crate, not
//  here. In the Starlight workspace that server is `starlight`, which
//  drives this codec from its `Worker` over a pulsar channel.
//
//  Depends on the Swift port of the `http` crate
//  (https://github.com/akvilary/http-model) for message types, exactly as
//  Rust's hyper depends on the `http` crate.
//
//  Layout:
//
//    Sources/HTTPCodec/
//    ├── HTTPCodec.swift              module prelude (@_exported import HTTP)
//    ├── Proto/H1/                    HTTP/1.1 wire codec
//    │   ├── H1Conn.swift             H1Conn<IO> + H1ConnError + DecodedHead  (hyper proto::h1::Conn)
//    │   ├── Http1ConnectionIO.swift  runtime I/O protocol                   (hyper rt::Read/Write)
//    │   ├── Encoder.swift            H1Encoder, EncodedHead, H1EncodeError   (hyper proto::h1::encode)
//    │   ├── Server.swift             ServerTransaction (keep-alive policy)   (hyper proto::h1::Server)
//    │   └── ByteSearch.swift         SWAR scanners                           (httparse helpers)
//    └── Tests/HTTPCodecTests/        smuggling regression suite (A17-A28 + v0.3 hardening)
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
        .package(path: "../http-model"),
    ],
    targets: [
        .target(
            name: "HTTPCodec",
            dependencies: [
                .product(name: "HTTPModel", package: "http-model"),
            ],
            path: "Sources/HTTPCodec",
            swiftSettings: baseSwiftSettings
        ),
        .executableTarget(
            name: "http-codec-bench",
            dependencies: ["HTTPCodec"],
            path: "Sources/http-codec-bench",
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
