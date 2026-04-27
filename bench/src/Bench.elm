module Bench exposing
    ( v1_64, v1_65, v1_256, v1_1024, v1_4096
    , v2_64, v2_65, v2_256, v2_1024, v2_4096
    , v3_64, v3_65, v3_256, v3_1024, v3_4096
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


## V3 (V2 + inlined ch)

@docs v3_64, v3_65, v3_256, v3_1024, v3_4096

-}

import Bytes exposing (Bytes)
import Bytes.Encode as Encode
import SHA256
import SHA256.V1
import SHA256.V3


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
