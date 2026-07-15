# Contributing to Cryptonite

Thanks for your interest in the project. Here is a short guide to building,
testing and style.

## Build and tests

You need CMake ≥ 3.16 and a C compiler (GCC/Clang/MinGW). See
[docs/building.md](docs/building.md) for details.

```sh
cmake -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Before opening a PR, please make sure that:

- the build passes with warnings as errors:
  `cmake -B build -DCRYPTONITE_WERROR=ON`;
- `ctest` is green (the `pkixUtest` test is currently marked as
  expected-to-fail because of an expired test certificate — that is not your
  regression);
- the examples in `examples/` run (return 0).

CI runs the same on Linux (GCC, `-Werror`) and Windows (MinGW), plus
ASan/UBSan, decoder fuzzing and CodeQL.

## Code style

The style is described in [`.clang-format`](.clang-format) (K&R braces, 4
spaces, 120 column limit, pointer next to the name). Format **only your new /
changed code** — we do not mass-reformat the historical codebase:

```sh
git clang-format origin/master
```

CI shows clang-format suggestions for the changed lines (advisory).

## Comments and documentation

- Comments in the existing code are in Ukrainian; please follow that language.
- Public functions in the headers are documented in Doxygen style
  (`/** ... @param ... @return ... */`) — the reference is generated from them
  (`doxygen Doxyfile`).
- Do not edit generated code: `src/asn1/`, `src/pkix/c/struct/`,
  `src/storage/c/struct/` (the ASN.1 structures are produced by the compiler).

## Cryptographic core

The algorithm implementations in `src/cryptonite/c/` are the certified part.
Change them (not comments) only when necessary and with tests on the relevant
test vectors; avoid cosmetic edits.

## Security

Report vulnerabilities privately, per [SECURITY.md](SECURITY.md), not through a
public issue or PR.
