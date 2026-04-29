# elm-cardano/sha2

Fast SHA-224, SHA-256, SHA-384 and SHA-512 hashing for Elm `Bytes`.

A drop-in replacement for [`folkertdev/elm-sha2`](https://package.elm-lang.org/packages/folkertdev/elm-sha2/latest/), with a faster implementation.

## API

```elm
import SHA256

SHA256.fromString "hello world"        -- Digest
SHA256.fromBytes bytes                 -- Digest
SHA256.fromByteValues [0x68, 0x69]     -- Digest

SHA256.toHex digest                    -- String
SHA256.toBase64 digest                 -- String
SHA256.toBytes digest                  -- Bytes
SHA256.toByteValues digest             -- List Int
```

The same API is exposed by `SHA224`, `SHA384` and `SHA512`.

See the [module docs](https://package.elm-lang.org/packages/elm-cardano/sha2/1.0.0/) for the full API.

## Install

```sh
elm install elm-cardano/sha2
```

## Performance

Performance is a first-class concern for this package. The 64 SHA-256 rounds
(and 80 SHA-512 rounds) are fully unrolled, with round constants inlined as
integer literals and all intermediate state held in flat `Int` let-bindings.
Block decoding uses `map5`/`map2` shapes that hit V8's fast paths for
`Decode.map`.

See [`bench/`](https://github.com/elm-cardano/sha2/tree/main/bench) for the full benchmarking setup.
See [`bench/REPORT.md`](https://github.com/elm-cardano/sha2/tree/main/bench/REPORT.md) for the history of attempted optimizations.

## Development

```sh
pnpm install
pnpm test           # run tests
pnpm review         # elm-review
pnpm format:check   # check formatting
pnpm bench:build    # build benchmarks
pnpm bench:test     # run benchmark correctness checks
```
