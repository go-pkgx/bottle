# bottle

[![pkg.go.dev](https://img.shields.io/badge/pkg.go.dev-bottle-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/go-pkgx/bottle)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)

The pure-Go **pkgx bottle client** — the shared backend of the pure-Go pkgx
family. It resolves a package's dependency closure from the pkgx pantry,
downloads the bottles from the configured `PKGX_DIST` (default: the signed
`oci://ghcr.io/go-pkgx/packages` registry; set `https://dist.pkgx.dev` for the
full unsigned upstream pantry), completes the implicit libc/gcc closure a
`FROM scratch` image needs, and execs through the pkgx glibc loader.
`CGO_ENABLED=0`, no runtime dependencies of its own.

Consumed by:

- [go-pkgx/pkgm](https://github.com/go-pkgx/pkgm) — the *installer*
- [go-pkgx/pkgx](https://github.com/go-pkgx/pkgx) — the *runtime*

so both tools share one source of truth for the bottle protocol.

## Highlights

- Reads `package.yml` + `versions.txt` from the pantry, BFS the runtime
  dependency closure, streams gzip/xz + tar into `PKGX_DIR`.
- **Soname-exact FROM-scratch completion**: walks each bottle's ELF
  `DT_NEEDED` and pulls the provider version that ships the exact soname an
  ABI needs (not merely the latest), so drifted sonames resolve.
- Embedded Mozilla CA bundle (`net/http` with no system trust store), pure-Go
  DNS.

## Where it is proven to work

This package reads formats it did not write — ELF and Mach-O headers, OCI
manifests, tar and xz streams — every one of them little-endian on the wire. So
any place that reads an integer through the host's byte order rather than
through `encoding/binary` is wrong on a big-endian machine and nowhere else,
and a compiler cannot see it. CI therefore does not stop at cross-compiling: it
**runs the suite** on seven runtimes that are not the host.

| lane | how |
| --- | --- |
| `test (arm64\|riscv64\|ppc64le\|s390x\|loong64, qemu)` | `go test -exec qemu-<arch>-static`, `-count=1` so a cached PASS from the host architecture cannot stand in for a run that never happened |
| `test (js/wasm, node)` | node 24. Go's js/wasm port takes `net/http` through the host's `fetch()` and the filesystem through the host's `fs` — two runtimes no other lane exercises. A browser that installs a signed bottle into its own store runs this code |
| `test (wasip1/wasm, wasmtime)` | a *different* wasm port with a different syscall surface: no network at all, and a filesystem only where one is granted. A package that installs bottles has to know which of the two it is on |

`s390x` is in the list because it is big-endian and nothing else here is. The
build matrix adds linux/darwin on amd64 and arm64 and both wasm targets, so
everything that runs also compiles with `CGO_ENABLED=0`.

BSD-3-Clause.
