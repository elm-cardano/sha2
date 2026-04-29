module Bench exposing
    ( ours_64, ours_65, ours_256, ours_1024, ours_4096
    , folkertdev_64, folkertdev_65, folkertdev_256, folkertdev_1024, folkertdev_4096
    , sha512_ours_128, sha512_ours_256, sha512_ours_1024, sha512_ours_4096
    , sha512_folkertdev_128, sha512_folkertdev_256, sha512_folkertdev_1024, sha512_folkertdev_4096
    )

{-| Benchmark functions for SHA-256 and SHA-512.

`ours` is the elm-cardano/sha2 implementation exposed by this package.
`folkertdev` is the original folkertdev/elm-sha2 implementation (vendored as a baseline).

Each function takes `()` and computes the hash on a pre-built input of the given size.
Useful with elm-bench:

```sh
elm-bench -f Bench.ours_64 -f Bench.folkertdev_64 "()"
elm-bench -f Bench.ours_65 -f Bench.folkertdev_65 "()"
elm-bench -f Bench.ours_256 -f Bench.folkertdev_256 "()"
elm-bench -f Bench.ours_1024 -f Bench.folkertdev_1024 "()"
elm-bench -f Bench.ours_4096 -f Bench.folkertdev_4096 "()"

elm-bench -f Bench.sha512_ours_128 -f Bench.sha512_folkertdev_128 "()"
elm-bench -f Bench.sha512_ours_256 -f Bench.sha512_folkertdev_256 "()"
elm-bench -f Bench.sha512_ours_1024 -f Bench.sha512_folkertdev_1024 "()"
elm-bench -f Bench.sha512_ours_4096 -f Bench.sha512_folkertdev_4096 "()"
```


## SHA-256 ours (elm-cardano/sha2)

@docs ours_64, ours_65, ours_256, ours_1024, ours_4096


## SHA-256 folkertdev (folkertdev/elm-sha2)

@docs folkertdev_64, folkertdev_65, folkertdev_256, folkertdev_1024, folkertdev_4096


## SHA-512 ours (elm-cardano/sha2)

@docs sha512_ours_128, sha512_ours_256, sha512_ours_1024, sha512_ours_4096


## SHA-512 folkertdev (folkertdev/elm-sha2)

@docs sha512_folkertdev_128, sha512_folkertdev_256, sha512_folkertdev_1024, sha512_folkertdev_4096

-}

import Bytes exposing (Bytes)
import Bytes.Encode as Encode
import SHA256
import SHA256.V1
import SHA512
import SHA512.V1


makeBytes : Int -> Bytes
makeBytes n =
    Encode.encode
        (Encode.sequence
            (List.map (\i -> Encode.unsignedInt8 (modBy 256 i)) (List.range 0 (n - 1)))
        )


bytes64 : Bytes
bytes64 =
    makeBytes 64


bytes65 : Bytes
bytes65 =
    makeBytes 65


bytes128 : Bytes
bytes128 =
    makeBytes 128


bytes256 : Bytes
bytes256 =
    makeBytes 256


bytes1024 : Bytes
bytes1024 =
    makeBytes 1024


bytes4096 : Bytes
bytes4096 =
    makeBytes 4096



-- SHA-256 ours (elm-cardano/sha2)


{-| ours SHA-256 on 64 bytes.
-}
ours_64 : () -> Bytes
ours_64 () =
    SHA256.fromBytes bytes64 |> SHA256.toBytes


{-| ours SHA-256 on 65 bytes.
-}
ours_65 : () -> Bytes
ours_65 () =
    SHA256.fromBytes bytes65 |> SHA256.toBytes


{-| ours SHA-256 on 256 bytes.
-}
ours_256 : () -> Bytes
ours_256 () =
    SHA256.fromBytes bytes256 |> SHA256.toBytes


{-| ours SHA-256 on 1024 bytes.
-}
ours_1024 : () -> Bytes
ours_1024 () =
    SHA256.fromBytes bytes1024 |> SHA256.toBytes


{-| ours SHA-256 on 4096 bytes.
-}
ours_4096 : () -> Bytes
ours_4096 () =
    SHA256.fromBytes bytes4096 |> SHA256.toBytes



-- SHA-256 folkertdev (folkertdev/elm-sha2)


{-| folkertdev SHA-256 on 64 bytes.
-}
folkertdev_64 : () -> Bytes
folkertdev_64 () =
    SHA256.V1.hash bytes64


{-| folkertdev SHA-256 on 65 bytes.
-}
folkertdev_65 : () -> Bytes
folkertdev_65 () =
    SHA256.V1.hash bytes65


{-| folkertdev SHA-256 on 256 bytes.
-}
folkertdev_256 : () -> Bytes
folkertdev_256 () =
    SHA256.V1.hash bytes256


{-| folkertdev SHA-256 on 1024 bytes.
-}
folkertdev_1024 : () -> Bytes
folkertdev_1024 () =
    SHA256.V1.hash bytes1024


{-| folkertdev SHA-256 on 4096 bytes.
-}
folkertdev_4096 : () -> Bytes
folkertdev_4096 () =
    SHA256.V1.hash bytes4096



-- SHA-512 ours (elm-cardano/sha2)


{-| ours SHA-512 on 128 bytes.
-}
sha512_ours_128 : () -> Bytes
sha512_ours_128 () =
    SHA512.fromBytes bytes128 |> SHA512.toBytes


{-| ours SHA-512 on 256 bytes.
-}
sha512_ours_256 : () -> Bytes
sha512_ours_256 () =
    SHA512.fromBytes bytes256 |> SHA512.toBytes


{-| ours SHA-512 on 1024 bytes.
-}
sha512_ours_1024 : () -> Bytes
sha512_ours_1024 () =
    SHA512.fromBytes bytes1024 |> SHA512.toBytes


{-| ours SHA-512 on 4096 bytes.
-}
sha512_ours_4096 : () -> Bytes
sha512_ours_4096 () =
    SHA512.fromBytes bytes4096 |> SHA512.toBytes



-- SHA-512 folkertdev (folkertdev/elm-sha2)


{-| folkertdev SHA-512 on 128 bytes.
-}
sha512_folkertdev_128 : () -> Bytes
sha512_folkertdev_128 () =
    SHA512.V1.hash bytes128


{-| folkertdev SHA-512 on 256 bytes.
-}
sha512_folkertdev_256 : () -> Bytes
sha512_folkertdev_256 () =
    SHA512.V1.hash bytes256


{-| folkertdev SHA-512 on 1024 bytes.
-}
sha512_folkertdev_1024 : () -> Bytes
sha512_folkertdev_1024 () =
    SHA512.V1.hash bytes1024


{-| folkertdev SHA-512 on 4096 bytes.
-}
sha512_folkertdev_4096 : () -> Bytes
sha512_folkertdev_4096 () =
    SHA512.V1.hash bytes4096
