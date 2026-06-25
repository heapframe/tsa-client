# tsa-client

A command-line RFC 3161 Time-Stamp Authority (TSA) client written in C++20.

Given any file, it computes a SHA-512 digest, sends a timestamp request to a TSA server, and saves a cryptographically-signed timestamp token that proves the file existed at a specific point in time. The timestamp can be verified offline at any point in the future.

## What is RFC 3161?

[RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161) is an IETF standard for trusted timestamping. A TSA (Time-Stamp Authority) is a trusted third party that signs a hash of your data along with the current time, producing a tamper-evident timestamp token (`.tsr`). This is used in legal documents, software signing, audit trails, and long-term archiving.

## Features

- SHA-512 file hashing via OpenSSL EVP API
- DER-encoded RFC 3161 timestamp request (`.tsq`) construction
- HTTPS POST to any RFC 3161-compliant TSA endpoint
- TSR response saved to disk and verified with `TS_RESP_verify_response`
- Configurable TSA server URL (defaults to [freetsa.org](https://freetsa.org))
- Embedded FreeTSA certificate bundle for offline trust verification (see below)
- 26 unit tests via Google Test

## Usage

```
tsa_client <filename> [tsa_server]
```

```sh
# Timestamp a file using the default TSA (freetsa.org)
tsa_client document.pdf

# Timestamp using a custom TSA
tsa_client document.pdf https://timestamp.apple.com/ts01

# Output
document.pdf.tsq   # The timestamp request sent to the TSA
document.pdf.tsr   # The signed timestamp token from the TSA
```

Some other public TSAs that work with this client:

- `https://freetsa.org/tsr` (default)
- `http://timestamp.apple.com/ts01`
- `https://rfc3161.ai.moda/microsoft`

## Build

**Dependencies:** CMake 3.25+, OpenSSL, libcurl, GTest (for tests)

```sh
cmake -S . -B build
cmake --build build
```

**Run tests:**

```sh
cmake --build build --target tsa_tests
ctest --test-dir build --output-on-failure
```

## Embedded Certificate Bundle (`ENABLE_FREETSA_BUNDLE`)

By default, the build flag `ENABLE_FREETSA_BUNDLE` is **ON**.

When enabled, CMake fetches the FreeTSA CA certificate and TSA certificate at build time, bundles them into a PEM file, and converts the bundle into a C header using `xxd`. This header is compiled directly into the binary — no certificate files need to be present at runtime.

This solves a real problem: FreeTSA uses a self-signed CA, which OpenSSL rejects by default. Rather than disabling chain verification entirely, this approach loads a pinned trust store containing only the FreeTSA certificates, so verification works correctly without weakening security.

### MITM protection

Before the certificates are embedded, the build system verifies each one against a known SHA-256 fingerprint:

```cmake
set(KNOWN_CA_FP  "sha256 Fingerprint=A6:37:9E:...")
set(KNOWN_CRT_FP "sha256 Fingerprint=32:E8:41:...")
```

If the fetched certificate does not match the expected fingerprint, a warning is emitted at build time. This means a compromised or swapped certificate cannot silently end up baked into your binary.

When a non-FreeTSA server is used at runtime, the embedded bundle is bypassed and OpenSSL falls back to the system certificate store.

To build without the embedded bundle (e.g. if you have FreeTSA's certs in your system store already):

```sh
cmake -S . -B build -DENABLE_FREETSA_BUNDLE=OFF
```

## Project Structure

```
tsa-client/
├── main.cpp              # Entry point: argument parsing, orchestration
├── file_io.cpp/.h        # read_file / write_file
├── tsa/
│   ├── tsa_crypto.cpp/.h # SHA-512 hashing, TSQ construction, TSR verification
│   └── tsa_network.cpp/.h# libcurl HTTP POST to TSA
├── tests/
│   ├── test_file_io.cpp
│   ├── test_tsa_crypto.cpp
│   └── test_tsa_network.cpp
└── CMakeLists.txt
```

## Dependencies

| Library / Tool | Purpose |
|---|---|
| [OpenSSL](https://www.openssl.org/) | SHA-512 hashing, RFC 3161 request/response types, TSR verification |
| [libcurl](https://curl.se/libcurl/) | HTTPS POST to TSA endpoint |
| [xxd](https://linux.die.net/man/1/xxd) | Converts the FreeTSA certificate bundle into a C header at build time (`ENABLE_FREETSA_BUNDLE=ON` only) |
| [Google Test](https://github.com/google/googletest) | Unit testing (build-time only) |
