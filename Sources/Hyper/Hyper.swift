//===----------------------------------------------------------------------===//
//
//  Hyper.swift
//  Hyper
//
//  lib.rs — module prelude + public re-exports.
//
//  Direct port of `hyper::lib` (https://docs.rs/hyper). The crate
//  re-exports the public surface of every submodule so users do
//  `import Hyper` and access everything as `Hyper.Body`, `Hyper.Conn`,
//  etc.
//
//===----------------------------------------------------------------------===//

import Foundation
@_exported import HTTP

// `HTTP` provides: Request, Response, HeaderMap, HeaderName,
// HeaderValue, Method, StatusCode, Uri, Version, Body, Extensions.
// Re-exported above via `@_exported`.
