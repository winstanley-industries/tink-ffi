# tink-ffi-sys

Raw FFI bindings to [Google Tink](https://github.com/tink-crypto/tink-cc) via a
C shim layer. This crate builds tink-cc from source and exposes its primitives as
`extern "C"` functions. Most users should prefer the safe
[`tink-ffi`](https://crates.io/crates/tink-ffi) crate, which wraps these
bindings in idiomatic, memory-safe Rust.

## Build requirements

- CMake 3.13+
- A C++17-capable compiler (GCC 7+, Clang 5+, or Apple Clang 10+)

The build downloads and compiles BoringSSL and Abseil automatically via CMake.
