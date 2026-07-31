# bottle

[![pkg.go.dev](https://img.shields.io/badge/pkg.go.dev-bottle-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/go-pkgx/bottle)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)

The pure-Go **pkgx bottle client** — the shared backend of the pure-Go pkgx
family. It resolves a package's dependency closure from the pkgx pantry,
downloads the bottles from `dist.pkgx.dev`, completes the implicit
libc/gcc closure a `FROM scratch` image needs, and execs through the pkgx
glibc loader. `CGO_ENABLED=0`, no runtime dependencies of its own.

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
  DNS. Cross-compiles to six 64-bit targets.

BSD-3-Clause.
