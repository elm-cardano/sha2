module Bench exposing
    ( v1_64, v1_65, v1_256, v1_1024, v1_4096
    , v2_64, v2_65, v2_256, v2_1024, v2_4096
    , v3_64, v3_65, v3_256, v3_1024, v3_4096
    , v4_64, v4_65, v4_256, v4_1024, v4_4096
    , v5_64, v5_65, v5_256, v5_1024, v5_4096
    , sha512v1_128, sha512v1_256, sha512v1_1024, sha512v1_4096
    , sha512_128, sha512_256, sha512_1024, sha512_4096
    , sha512v3_128, sha512v3_256, sha512v3_1024, sha512v3_4096
    )

{-| Benchmark functions for SHA-256.

V1 is the original folkertdev/elm-sha2 implementation.
V2 is the new elm-cardano/sha2 optimized implementation.
V3 is V2 with ch inlined as raw bitwise operations.

Each function takes `()` and computes SHA-256 on a pre-built input of the given size.
Useful with elm-bench:

```sh
elm-bench -f Bench.v1_64 -f Bench.v2_64 -f Bench.v3_64 "()"
elm-bench -f Bench.v1_65 -f Bench.v2_65 -f Bench.v3_65 "()"
elm-bench -f Bench.v1_256 -f Bench.v2_256 -f Bench.v3_256 "()"
elm-bench -f Bench.v1_1024 -f Bench.v2_1024 -f Bench.v3_1024 "()"
elm-bench -f Bench.v1_4096 -f Bench.v2_4096 -f Bench.v3_4096 "()"
```


## V1 (folkertdev/elm-sha2)

@docs v1_64, v1_65, v1_256, v1_1024, v1_4096


## V2 (elm-cardano/sha2)

@docs v2_64, v2_65, v2_256, v2_1024, v2_4096


## V3 (V2 + inlined ch/maj)

@docs v3_64, v3_65, v3_256, v3_1024, v3_4096


## V4 (V3 + removed unsigned)

@docs v4_64, v4_65, v4_256, v4_1024, v4_4096


## V5 (V4 + twoRounds factoring)

@docs v5_64, v5_65, v5_256, v5_1024, v5_4096


## SHA-512 V1 (folkertdev/elm-sha2 baseline)

@docs sha512v1_128, sha512v1_256, sha512v1_1024, sha512v1_4096


## SHA-512 optimized (elm-cardano/sha2)

@docs sha512_128, sha512_256, sha512_1024, sha512_4096


## SHA-512 V3 (experimental)

@docs sha512v3_128, sha512v3_256, sha512v3_1024, sha512v3_4096

-}

import Bytes exposing (Bytes)
import Bytes.Encode as Encode
import SHA256
import SHA256.V1
import SHA256.V3
import SHA256.V4
import SHA256.V5
import SHA512
import SHA512.V1
import SHA512.V3


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


bytes256 : Bytes
bytes256 =
    makeBytes 256


bytes1024 : Bytes
bytes1024 =
    makeBytes 1024


bytes4096 : Bytes
bytes4096 =
    makeBytes 4096



-- V1 (folkertdev/elm-sha2)


{-| V1 SHA-256 on 64 bytes.
-}
v1_64 : () -> Bytes
v1_64 () =
    SHA256.V1.hash bytes64


{-| V1 SHA-256 on 65 bytes.
-}
v1_65 : () -> Bytes
v1_65 () =
    SHA256.V1.hash bytes65


{-| V1 SHA-256 on 256 bytes.
-}
v1_256 : () -> Bytes
v1_256 () =
    SHA256.V1.hash bytes256


{-| V1 SHA-256 on 1024 bytes.
-}
v1_1024 : () -> Bytes
v1_1024 () =
    SHA256.V1.hash bytes1024


{-| V1 SHA-256 on 4096 bytes.
-}
v1_4096 : () -> Bytes
v1_4096 () =
    SHA256.V1.hash bytes4096



-- V2 (elm-cardano/sha2)


{-| V2 SHA-256 on 64 bytes.
-}
v2_64 : () -> Bytes
v2_64 () =
    SHA256.fromBytes bytes64 |> SHA256.toBytes


{-| V2 SHA-256 on 65 bytes.
-}
v2_65 : () -> Bytes
v2_65 () =
    SHA256.fromBytes bytes65 |> SHA256.toBytes


{-| V2 SHA-256 on 256 bytes.
-}
v2_256 : () -> Bytes
v2_256 () =
    SHA256.fromBytes bytes256 |> SHA256.toBytes


{-| V2 SHA-256 on 1024 bytes.
-}
v2_1024 : () -> Bytes
v2_1024 () =
    SHA256.fromBytes bytes1024 |> SHA256.toBytes


{-| V2 SHA-256 on 4096 bytes.
-}
v2_4096 : () -> Bytes
v2_4096 () =
    SHA256.fromBytes bytes4096 |> SHA256.toBytes



-- V3 (V2 + inlined ch)


{-| V3 SHA-256 on 64 bytes.
-}
v3_64 : () -> Bytes
v3_64 () =
    SHA256.V3.hash bytes64


{-| V3 SHA-256 on 65 bytes.
-}
v3_65 : () -> Bytes
v3_65 () =
    SHA256.V3.hash bytes65


{-| V3 SHA-256 on 256 bytes.
-}
v3_256 : () -> Bytes
v3_256 () =
    SHA256.V3.hash bytes256


{-| V3 SHA-256 on 1024 bytes.
-}
v3_1024 : () -> Bytes
v3_1024 () =
    SHA256.V3.hash bytes1024


{-| V3 SHA-256 on 4096 bytes.
-}
v3_4096 : () -> Bytes
v3_4096 () =
    SHA256.V3.hash bytes4096



-- V4 (V3 + removed unsigned)


{-| V4 SHA-256 on 64 bytes.
-}
v4_64 : () -> Bytes
v4_64 () =
    SHA256.V4.hash bytes64


{-| V4 SHA-256 on 65 bytes.
-}
v4_65 : () -> Bytes
v4_65 () =
    SHA256.V4.hash bytes65


{-| V4 SHA-256 on 256 bytes.
-}
v4_256 : () -> Bytes
v4_256 () =
    SHA256.V4.hash bytes256


{-| V4 SHA-256 on 1024 bytes.
-}
v4_1024 : () -> Bytes
v4_1024 () =
    SHA256.V4.hash bytes1024


{-| V4 SHA-256 on 4096 bytes.
-}
v4_4096 : () -> Bytes
v4_4096 () =
    SHA256.V4.hash bytes4096



-- V5 (V4 + twoRounds factoring)


{-| V5 SHA-256 on 64 bytes.
-}
v5_64 : () -> Bytes
v5_64 () =
    SHA256.V5.hash bytes64


{-| V5 SHA-256 on 65 bytes.
-}
v5_65 : () -> Bytes
v5_65 () =
    SHA256.V5.hash bytes65


{-| V5 SHA-256 on 256 bytes.
-}
v5_256 : () -> Bytes
v5_256 () =
    SHA256.V5.hash bytes256


{-| V5 SHA-256 on 1024 bytes.
-}
v5_1024 : () -> Bytes
v5_1024 () =
    SHA256.V5.hash bytes1024


{-| V5 SHA-256 on 4096 bytes.
-}
v5_4096 : () -> Bytes
v5_4096 () =
    SHA256.V5.hash bytes4096



-- SHA-512 V1 (baseline)


bytes128 : Bytes
bytes128 =
    makeBytes 128


{-| SHA-512 V1 on 128 bytes.
-}
sha512v1_128 : () -> Bytes
sha512v1_128 () =
    SHA512.V1.hash bytes128


{-| SHA-512 V1 on 256 bytes.
-}
sha512v1_256 : () -> Bytes
sha512v1_256 () =
    SHA512.V1.hash bytes256


{-| SHA-512 V1 on 1024 bytes.
-}
sha512v1_1024 : () -> Bytes
sha512v1_1024 () =
    SHA512.V1.hash bytes1024


{-| SHA-512 V1 on 4096 bytes.
-}
sha512v1_4096 : () -> Bytes
sha512v1_4096 () =
    SHA512.V1.hash bytes4096



-- SHA-512 (optimized)


{-| SHA-512 optimized on 128 bytes.
-}
sha512_128 : () -> Bytes
sha512_128 () =
    SHA512.fromBytes bytes128 |> SHA512.toBytes


{-| SHA-512 optimized on 256 bytes.
-}
sha512_256 : () -> Bytes
sha512_256 () =
    SHA512.fromBytes bytes256 |> SHA512.toBytes


{-| SHA-512 optimized on 1024 bytes.
-}
sha512_1024 : () -> Bytes
sha512_1024 () =
    SHA512.fromBytes bytes1024 |> SHA512.toBytes


{-| SHA-512 optimized on 4096 bytes.
-}
sha512_4096 : () -> Bytes
sha512_4096 () =
    SHA512.fromBytes bytes4096 |> SHA512.toBytes



-- SHA-512 V3 (experimental)


{-| SHA-512 V3 on 128 bytes.
-}
sha512v3_128 : () -> Bytes
sha512v3_128 () =
    SHA512.V3.hash bytes128


{-| SHA-512 V3 on 256 bytes.
-}
sha512v3_256 : () -> Bytes
sha512v3_256 () =
    SHA512.V3.hash bytes256


{-| SHA-512 V3 on 1024 bytes.
-}
sha512v3_1024 : () -> Bytes
sha512v3_1024 () =
    SHA512.V3.hash bytes1024


{-| SHA-512 V3 on 4096 bytes.
-}
sha512v3_4096 : () -> Bytes
sha512v3_4096 () =
    SHA512.V3.hash bytes4096
