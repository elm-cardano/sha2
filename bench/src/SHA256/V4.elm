module SHA256.V4 exposing
    ( hash
    )

{-| SHA-256 V4: ch/maj inlined + most unsigned calls removed.

@docs hash

-}

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode


{-| An abstract sha256 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int Int



-- Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).
-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        byteCount =
            Bytes.width bytes

        remainderMod64 =
            byteCount |> modBy 64

        paddingZeros =
            if remainderMod64 < 56 then
                55 - remainderMod64

            else
                119 - remainderMod64

        bitLenHi =
            Bitwise.shiftRightZfBy 29 byteCount

        bitLenLo =
            Bitwise.shiftLeftBy 3 byteCount |> unsigned

        paddedBytes =
            Encode.encode
                (Encode.sequence
                    [ Encode.bytes bytes
                    , Encode.unsignedInt8 0x80
                    , Encode.sequence (List.repeat (paddingZeros // 4) (Encode.unsignedInt32 BE 0))
                    , Encode.sequence (List.repeat (paddingZeros |> modBy 4) (Encode.unsignedInt8 0))
                    , Encode.unsignedInt32 BE bitLenHi
                    , Encode.unsignedInt32 BE bitLenLo
                    ]
                )

        totalBlocks =
            Bytes.width paddedBytes // 64
    in
    case Decode.decode (blocksDecoder totalBlocks) paddedBytes of
        Just digest ->
            digest

        Nothing ->
            Digest 0 0 0 0 0 0 0 0


blocksDecoder : Int -> Decoder Digest
blocksDecoder totalBlocks =
    Decode.loop
        { remaining = totalBlocks
        , h0 = 0x6A09E667
        , h1 = 0xBB67AE85
        , h2 = 0x3C6EF372
        , h3 = 0xA54FF53A
        , h4 = 0x510E527F
        , h5 = 0x9B05688C
        , h6 = 0x1F83D9AB
        , h7 = 0x5BE0CD19
        }
        blockStep


type alias BlockState =
    { remaining : Int
    , h0 : Int
    , h1 : Int
    , h2 : Int
    , h3 : Int
    , h4 : Int
    , h5 : Int
    , h6 : Int
    , h7 : Int
    }


{-| 8 message words, decoded as a half-block. Record constructor is F8, within Elm's fast path.
-}
type alias HalfBlock =
    { w0 : Int
    , w1 : Int
    , w2 : Int
    , w3 : Int
    , w4 : Int
    , w5 : Int
    , w6 : Int
    , w7 : Int
    }


blockStep : BlockState -> Decoder (Step BlockState Digest)
blockStep state =
    if state.remaining <= 0 then
        Decode.succeed (Done (Digest state.h0 state.h1 state.h2 state.h3 state.h4 state.h5 state.h6 state.h7))

    else
        Decode.map2
            (\first second ->
                let
                    result =
                        compress state first second
                in
                Loop
                    { remaining = state.remaining - 1
                    , h0 = result.h0
                    , h1 = result.h1
                    , h2 = result.h2
                    , h3 = result.h3
                    , h4 = result.h4
                    , h5 = result.h5
                    , h6 = result.h6
                    , h7 = result.h7
                    }
            )
            halfBlockDecoder
            halfBlockDecoder


{-| Decode 8 big-endian u32 words. Uses map5 with nested pairs to stay within
Elm's F2..F9 fast-call path (callback is F5, record constructor is F8).
-}
halfBlockDecoder : Decoder HalfBlock
halfBlockDecoder =
    Decode.map5
        (\a b ( c, d ) ( e, f ) ( g, h ) -> HalfBlock a b c d e f g h)
        u32
        u32
        (Decode.map2 Tuple.pair u32 u32)
        (Decode.map2 Tuple.pair u32 u32)
        (Decode.map2 Tuple.pair u32 u32)


u32 : Decoder Int
u32 =
    Decode.unsignedInt32 BE


{-| SHA-256 compression function. Takes the current hash state and 16 message words
(as two HalfBlocks), expands the message schedule and runs all 64 rounds.

All w values, schedule words, and round state are flat Int let-bindings to minimize
allocations. Round constants (k) are inlined as literals.
-}
compress : BlockState -> HalfBlock -> HalfBlock -> { h0 : Int, h1 : Int, h2 : Int, h3 : Int, h4 : Int, h5 : Int, h6 : Int, h7 : Int }
compress state first second =
    let
        -- Bind record fields to local variables (one-time access)
        h0 =
            state.h0

        h1 =
            state.h1

        h2 =
            state.h2

        h3 =
            state.h3

        h4 =
            state.h4

        h5 =
            state.h5

        h6 =
            state.h6

        h7 =
            state.h7

        w0 =
            first.w0

        w1 =
            first.w1

        w2 =
            first.w2

        w3 =
            first.w3

        w4 =
            first.w4

        w5 =
            first.w5

        w6 =
            first.w6

        w7 =
            first.w7

        w8 =
            second.w0

        w9 =
            second.w1

        w10 =
            second.w2

        w11 =
            second.w3

        w12 =
            second.w4

        w13 =
            second.w5

        w14 =
            second.w6

        w15 =
            second.w7

        -- Message schedule expansion w16..w63
        w16 =
            ssig1 w14 + w9 + ssig0 w1 + w0

        w17 =
            ssig1 w15 + w10 + ssig0 w2 + w1

        w18 =
            ssig1 w16 + w11 + ssig0 w3 + w2

        w19 =
            ssig1 w17 + w12 + ssig0 w4 + w3

        w20 =
            ssig1 w18 + w13 + ssig0 w5 + w4

        w21 =
            ssig1 w19 + w14 + ssig0 w6 + w5

        w22 =
            ssig1 w20 + w15 + ssig0 w7 + w6

        w23 =
            ssig1 w21 + w16 + ssig0 w8 + w7

        w24 =
            ssig1 w22 + w17 + ssig0 w9 + w8

        w25 =
            ssig1 w23 + w18 + ssig0 w10 + w9

        w26 =
            ssig1 w24 + w19 + ssig0 w11 + w10

        w27 =
            ssig1 w25 + w20 + ssig0 w12 + w11

        w28 =
            ssig1 w26 + w21 + ssig0 w13 + w12

        w29 =
            ssig1 w27 + w22 + ssig0 w14 + w13

        w30 =
            ssig1 w28 + w23 + ssig0 w15 + w14

        w31 =
            ssig1 w29 + w24 + ssig0 w16 + w15

        w32 =
            ssig1 w30 + w25 + ssig0 w17 + w16

        w33 =
            ssig1 w31 + w26 + ssig0 w18 + w17

        w34 =
            ssig1 w32 + w27 + ssig0 w19 + w18

        w35 =
            ssig1 w33 + w28 + ssig0 w20 + w19

        w36 =
            ssig1 w34 + w29 + ssig0 w21 + w20

        w37 =
            ssig1 w35 + w30 + ssig0 w22 + w21

        w38 =
            ssig1 w36 + w31 + ssig0 w23 + w22

        w39 =
            ssig1 w37 + w32 + ssig0 w24 + w23

        w40 =
            ssig1 w38 + w33 + ssig0 w25 + w24

        w41 =
            ssig1 w39 + w34 + ssig0 w26 + w25

        w42 =
            ssig1 w40 + w35 + ssig0 w27 + w26

        w43 =
            ssig1 w41 + w36 + ssig0 w28 + w27

        w44 =
            ssig1 w42 + w37 + ssig0 w29 + w28

        w45 =
            ssig1 w43 + w38 + ssig0 w30 + w29

        w46 =
            ssig1 w44 + w39 + ssig0 w31 + w30

        w47 =
            ssig1 w45 + w40 + ssig0 w32 + w31

        w48 =
            ssig1 w46 + w41 + ssig0 w33 + w32

        w49 =
            ssig1 w47 + w42 + ssig0 w34 + w33

        w50 =
            ssig1 w48 + w43 + ssig0 w35 + w34

        w51 =
            ssig1 w49 + w44 + ssig0 w36 + w35

        w52 =
            ssig1 w50 + w45 + ssig0 w37 + w36

        w53 =
            ssig1 w51 + w46 + ssig0 w38 + w37

        w54 =
            ssig1 w52 + w47 + ssig0 w39 + w38

        w55 =
            ssig1 w53 + w48 + ssig0 w40 + w39

        w56 =
            ssig1 w54 + w49 + ssig0 w41 + w40

        w57 =
            ssig1 w55 + w50 + ssig0 w42 + w41

        w58 =
            ssig1 w56 + w51 + ssig0 w43 + w42

        w59 =
            ssig1 w57 + w52 + ssig0 w44 + w43

        w60 =
            ssig1 w58 + w53 + ssig0 w45 + w44

        w61 =
            ssig1 w59 + w54 + ssig0 w46 + w45

        w62 =
            ssig1 w60 + w55 + ssig0 w47 + w46

        w63 =
            ssig1 w61 + w56 + ssig0 w48 + w47

        -- 64 compression rounds, fully unrolled with inlined round constants.
        -- We track only a (arN) and e (erN); b,c,d are previous a's; f,g,h are previous e's.
        -- Round 0
        t1r0 =
            h7 + bsig1 h4 + Bitwise.xor h6 (Bitwise.and h4 (Bitwise.xor h5 h6)) + 0x428A2F98 + w0

        t2r0 =
            bsig0 h0 + Bitwise.xor (Bitwise.xor (Bitwise.and h0 h1) (Bitwise.and h0 h2)) (Bitwise.and h1 h2)

        ar0 =
            t1r0 + t2r0

        er0 =
            h3 + t1r0

        -- Round 1
        t1r1 =
            h6 + bsig1 er0 + Bitwise.xor h5 (Bitwise.and er0 (Bitwise.xor h4 h5)) + 0x71374491 + w1

        t2r1 =
            bsig0 ar0 + Bitwise.xor (Bitwise.xor (Bitwise.and ar0 h0) (Bitwise.and ar0 h1)) (Bitwise.and h0 h1)

        ar1 =
            t1r1 + t2r1

        er1 =
            h2 + t1r1

        -- Round 2
        t1r2 =
            h5 + bsig1 er1 + Bitwise.xor h4 (Bitwise.and er1 (Bitwise.xor er0 h4)) + 0xB5C0FBCF + w2

        t2r2 =
            bsig0 ar1 + Bitwise.xor (Bitwise.xor (Bitwise.and ar1 ar0) (Bitwise.and ar1 h0)) (Bitwise.and ar0 h0)

        ar2 =
            t1r2 + t2r2

        er2 =
            h1 + t1r2

        -- Round 3
        t1r3 =
            h4 + bsig1 er2 + Bitwise.xor er0 (Bitwise.and er2 (Bitwise.xor er1 er0)) + 0xE9B5DBA5 + w3

        t2r3 =
            bsig0 ar2 + Bitwise.xor (Bitwise.xor (Bitwise.and ar2 ar1) (Bitwise.and ar2 ar0)) (Bitwise.and ar1 ar0)

        ar3 =
            t1r3 + t2r3

        er3 =
            h0 + t1r3

        -- Round 4
        t1r4 =
            er0 + bsig1 er3 + Bitwise.xor er1 (Bitwise.and er3 (Bitwise.xor er2 er1)) + 0x3956C25B + w4

        t2r4 =
            bsig0 ar3 + Bitwise.xor (Bitwise.xor (Bitwise.and ar3 ar2) (Bitwise.and ar3 ar1)) (Bitwise.and ar2 ar1)

        ar4 =
            t1r4 + t2r4

        er4 =
            ar0 + t1r4

        -- Round 5
        t1r5 =
            er1 + bsig1 er4 + Bitwise.xor er2 (Bitwise.and er4 (Bitwise.xor er3 er2)) + 0x59F111F1 + w5

        t2r5 =
            bsig0 ar4 + Bitwise.xor (Bitwise.xor (Bitwise.and ar4 ar3) (Bitwise.and ar4 ar2)) (Bitwise.and ar3 ar2)

        ar5 =
            t1r5 + t2r5

        er5 =
            ar1 + t1r5

        -- Round 6
        t1r6 =
            er2 + bsig1 er5 + Bitwise.xor er3 (Bitwise.and er5 (Bitwise.xor er4 er3)) + 0x923F82A4 + w6

        t2r6 =
            bsig0 ar5 + Bitwise.xor (Bitwise.xor (Bitwise.and ar5 ar4) (Bitwise.and ar5 ar3)) (Bitwise.and ar4 ar3)

        ar6 =
            t1r6 + t2r6

        er6 =
            ar2 + t1r6

        -- Round 7
        t1r7 =
            er3 + bsig1 er6 + Bitwise.xor er4 (Bitwise.and er6 (Bitwise.xor er5 er4)) + 0xAB1C5ED5 + w7

        t2r7 =
            bsig0 ar6 + Bitwise.xor (Bitwise.xor (Bitwise.and ar6 ar5) (Bitwise.and ar6 ar4)) (Bitwise.and ar5 ar4)

        ar7 =
            t1r7 + t2r7

        er7 =
            ar3 + t1r7

        -- Round 8
        t1r8 =
            er4 + bsig1 er7 + Bitwise.xor er5 (Bitwise.and er7 (Bitwise.xor er6 er5)) + 0xD807AA98 + w8

        t2r8 =
            bsig0 ar7 + Bitwise.xor (Bitwise.xor (Bitwise.and ar7 ar6) (Bitwise.and ar7 ar5)) (Bitwise.and ar6 ar5)

        ar8 =
            t1r8 + t2r8

        er8 =
            ar4 + t1r8

        -- Round 9
        t1r9 =
            er5 + bsig1 er8 + Bitwise.xor er6 (Bitwise.and er8 (Bitwise.xor er7 er6)) + 0x12835B01 + w9

        t2r9 =
            bsig0 ar8 + Bitwise.xor (Bitwise.xor (Bitwise.and ar8 ar7) (Bitwise.and ar8 ar6)) (Bitwise.and ar7 ar6)

        ar9 =
            t1r9 + t2r9

        er9 =
            ar5 + t1r9

        -- Round 10
        t1r10 =
            er6 + bsig1 er9 + Bitwise.xor er7 (Bitwise.and er9 (Bitwise.xor er8 er7)) + 0x243185BE + w10

        t2r10 =
            bsig0 ar9 + Bitwise.xor (Bitwise.xor (Bitwise.and ar9 ar8) (Bitwise.and ar9 ar7)) (Bitwise.and ar8 ar7)

        ar10 =
            t1r10 + t2r10

        er10 =
            ar6 + t1r10

        -- Round 11
        t1r11 =
            er7 + bsig1 er10 + Bitwise.xor er8 (Bitwise.and er10 (Bitwise.xor er9 er8)) + 0x550C7DC3 + w11

        t2r11 =
            bsig0 ar10 + Bitwise.xor (Bitwise.xor (Bitwise.and ar10 ar9) (Bitwise.and ar10 ar8)) (Bitwise.and ar9 ar8)

        ar11 =
            t1r11 + t2r11

        er11 =
            ar7 + t1r11

        -- Round 12
        t1r12 =
            er8 + bsig1 er11 + Bitwise.xor er9 (Bitwise.and er11 (Bitwise.xor er10 er9)) + 0x72BE5D74 + w12

        t2r12 =
            bsig0 ar11 + Bitwise.xor (Bitwise.xor (Bitwise.and ar11 ar10) (Bitwise.and ar11 ar9)) (Bitwise.and ar10 ar9)

        ar12 =
            t1r12 + t2r12

        er12 =
            ar8 + t1r12

        -- Round 13
        t1r13 =
            er9 + bsig1 er12 + Bitwise.xor er10 (Bitwise.and er12 (Bitwise.xor er11 er10)) + 0x80DEB1FE + w13

        t2r13 =
            bsig0 ar12 + Bitwise.xor (Bitwise.xor (Bitwise.and ar12 ar11) (Bitwise.and ar12 ar10)) (Bitwise.and ar11 ar10)

        ar13 =
            t1r13 + t2r13

        er13 =
            ar9 + t1r13

        -- Round 14
        t1r14 =
            er10 + bsig1 er13 + Bitwise.xor er11 (Bitwise.and er13 (Bitwise.xor er12 er11)) + 0x9BDC06A7 + w14

        t2r14 =
            bsig0 ar13 + Bitwise.xor (Bitwise.xor (Bitwise.and ar13 ar12) (Bitwise.and ar13 ar11)) (Bitwise.and ar12 ar11)

        ar14 =
            t1r14 + t2r14

        er14 =
            ar10 + t1r14

        -- Round 15
        t1r15 =
            er11 + bsig1 er14 + Bitwise.xor er12 (Bitwise.and er14 (Bitwise.xor er13 er12)) + 0xC19BF174 + w15

        t2r15 =
            bsig0 ar14 + Bitwise.xor (Bitwise.xor (Bitwise.and ar14 ar13) (Bitwise.and ar14 ar12)) (Bitwise.and ar13 ar12)

        ar15 =
            t1r15 + t2r15

        er15 =
            ar11 + t1r15

        -- Round 16
        t1r16 =
            er12 + bsig1 er15 + Bitwise.xor er13 (Bitwise.and er15 (Bitwise.xor er14 er13)) + 0xE49B69C1 + w16

        t2r16 =
            bsig0 ar15 + Bitwise.xor (Bitwise.xor (Bitwise.and ar15 ar14) (Bitwise.and ar15 ar13)) (Bitwise.and ar14 ar13)

        ar16 =
            t1r16 + t2r16

        er16 =
            ar12 + t1r16

        -- Round 17
        t1r17 =
            er13 + bsig1 er16 + Bitwise.xor er14 (Bitwise.and er16 (Bitwise.xor er15 er14)) + 0xEFBE4786 + w17

        t2r17 =
            bsig0 ar16 + Bitwise.xor (Bitwise.xor (Bitwise.and ar16 ar15) (Bitwise.and ar16 ar14)) (Bitwise.and ar15 ar14)

        ar17 =
            t1r17 + t2r17

        er17 =
            ar13 + t1r17

        -- Round 18
        t1r18 =
            er14 + bsig1 er17 + Bitwise.xor er15 (Bitwise.and er17 (Bitwise.xor er16 er15)) + 0x0FC19DC6 + w18

        t2r18 =
            bsig0 ar17 + Bitwise.xor (Bitwise.xor (Bitwise.and ar17 ar16) (Bitwise.and ar17 ar15)) (Bitwise.and ar16 ar15)

        ar18 =
            t1r18 + t2r18

        er18 =
            ar14 + t1r18

        -- Round 19
        t1r19 =
            er15 + bsig1 er18 + Bitwise.xor er16 (Bitwise.and er18 (Bitwise.xor er17 er16)) + 0x240CA1CC + w19

        t2r19 =
            bsig0 ar18 + Bitwise.xor (Bitwise.xor (Bitwise.and ar18 ar17) (Bitwise.and ar18 ar16)) (Bitwise.and ar17 ar16)

        ar19 =
            t1r19 + t2r19

        er19 =
            ar15 + t1r19

        -- Round 20
        t1r20 =
            er16 + bsig1 er19 + Bitwise.xor er17 (Bitwise.and er19 (Bitwise.xor er18 er17)) + 0x2DE92C6F + w20

        t2r20 =
            bsig0 ar19 + Bitwise.xor (Bitwise.xor (Bitwise.and ar19 ar18) (Bitwise.and ar19 ar17)) (Bitwise.and ar18 ar17)

        ar20 =
            t1r20 + t2r20

        er20 =
            ar16 + t1r20

        -- Round 21
        t1r21 =
            er17 + bsig1 er20 + Bitwise.xor er18 (Bitwise.and er20 (Bitwise.xor er19 er18)) + 0x4A7484AA + w21

        t2r21 =
            bsig0 ar20 + Bitwise.xor (Bitwise.xor (Bitwise.and ar20 ar19) (Bitwise.and ar20 ar18)) (Bitwise.and ar19 ar18)

        ar21 =
            t1r21 + t2r21

        er21 =
            ar17 + t1r21

        -- Round 22
        t1r22 =
            er18 + bsig1 er21 + Bitwise.xor er19 (Bitwise.and er21 (Bitwise.xor er20 er19)) + 0x5CB0A9DC + w22

        t2r22 =
            bsig0 ar21 + Bitwise.xor (Bitwise.xor (Bitwise.and ar21 ar20) (Bitwise.and ar21 ar19)) (Bitwise.and ar20 ar19)

        ar22 =
            t1r22 + t2r22

        er22 =
            ar18 + t1r22

        -- Round 23
        t1r23 =
            er19 + bsig1 er22 + Bitwise.xor er20 (Bitwise.and er22 (Bitwise.xor er21 er20)) + 0x76F988DA + w23

        t2r23 =
            bsig0 ar22 + Bitwise.xor (Bitwise.xor (Bitwise.and ar22 ar21) (Bitwise.and ar22 ar20)) (Bitwise.and ar21 ar20)

        ar23 =
            t1r23 + t2r23

        er23 =
            ar19 + t1r23

        -- Round 24
        t1r24 =
            er20 + bsig1 er23 + Bitwise.xor er21 (Bitwise.and er23 (Bitwise.xor er22 er21)) + 0x983E5152 + w24

        t2r24 =
            bsig0 ar23 + Bitwise.xor (Bitwise.xor (Bitwise.and ar23 ar22) (Bitwise.and ar23 ar21)) (Bitwise.and ar22 ar21)

        ar24 =
            t1r24 + t2r24

        er24 =
            ar20 + t1r24

        -- Round 25
        t1r25 =
            er21 + bsig1 er24 + Bitwise.xor er22 (Bitwise.and er24 (Bitwise.xor er23 er22)) + 0xA831C66D + w25

        t2r25 =
            bsig0 ar24 + Bitwise.xor (Bitwise.xor (Bitwise.and ar24 ar23) (Bitwise.and ar24 ar22)) (Bitwise.and ar23 ar22)

        ar25 =
            t1r25 + t2r25

        er25 =
            ar21 + t1r25

        -- Round 26
        t1r26 =
            er22 + bsig1 er25 + Bitwise.xor er23 (Bitwise.and er25 (Bitwise.xor er24 er23)) + 0xB00327C8 + w26

        t2r26 =
            bsig0 ar25 + Bitwise.xor (Bitwise.xor (Bitwise.and ar25 ar24) (Bitwise.and ar25 ar23)) (Bitwise.and ar24 ar23)

        ar26 =
            t1r26 + t2r26

        er26 =
            ar22 + t1r26

        -- Round 27
        t1r27 =
            er23 + bsig1 er26 + Bitwise.xor er24 (Bitwise.and er26 (Bitwise.xor er25 er24)) + 0xBF597FC7 + w27

        t2r27 =
            bsig0 ar26 + Bitwise.xor (Bitwise.xor (Bitwise.and ar26 ar25) (Bitwise.and ar26 ar24)) (Bitwise.and ar25 ar24)

        ar27 =
            t1r27 + t2r27

        er27 =
            ar23 + t1r27

        -- Round 28
        t1r28 =
            er24 + bsig1 er27 + Bitwise.xor er25 (Bitwise.and er27 (Bitwise.xor er26 er25)) + 0xC6E00BF3 + w28

        t2r28 =
            bsig0 ar27 + Bitwise.xor (Bitwise.xor (Bitwise.and ar27 ar26) (Bitwise.and ar27 ar25)) (Bitwise.and ar26 ar25)

        ar28 =
            t1r28 + t2r28

        er28 =
            ar24 + t1r28

        -- Round 29
        t1r29 =
            er25 + bsig1 er28 + Bitwise.xor er26 (Bitwise.and er28 (Bitwise.xor er27 er26)) + 0xD5A79147 + w29

        t2r29 =
            bsig0 ar28 + Bitwise.xor (Bitwise.xor (Bitwise.and ar28 ar27) (Bitwise.and ar28 ar26)) (Bitwise.and ar27 ar26)

        ar29 =
            t1r29 + t2r29

        er29 =
            ar25 + t1r29

        -- Round 30
        t1r30 =
            er26 + bsig1 er29 + Bitwise.xor er27 (Bitwise.and er29 (Bitwise.xor er28 er27)) + 0x06CA6351 + w30

        t2r30 =
            bsig0 ar29 + Bitwise.xor (Bitwise.xor (Bitwise.and ar29 ar28) (Bitwise.and ar29 ar27)) (Bitwise.and ar28 ar27)

        ar30 =
            t1r30 + t2r30

        er30 =
            ar26 + t1r30

        -- Round 31
        t1r31 =
            er27 + bsig1 er30 + Bitwise.xor er28 (Bitwise.and er30 (Bitwise.xor er29 er28)) + 0x14292967 + w31

        t2r31 =
            bsig0 ar30 + Bitwise.xor (Bitwise.xor (Bitwise.and ar30 ar29) (Bitwise.and ar30 ar28)) (Bitwise.and ar29 ar28)

        ar31 =
            t1r31 + t2r31

        er31 =
            ar27 + t1r31

        -- Round 32
        t1r32 =
            er28 + bsig1 er31 + Bitwise.xor er29 (Bitwise.and er31 (Bitwise.xor er30 er29)) + 0x27B70A85 + w32

        t2r32 =
            bsig0 ar31 + Bitwise.xor (Bitwise.xor (Bitwise.and ar31 ar30) (Bitwise.and ar31 ar29)) (Bitwise.and ar30 ar29)

        ar32 =
            t1r32 + t2r32

        er32 =
            ar28 + t1r32

        -- Round 33
        t1r33 =
            er29 + bsig1 er32 + Bitwise.xor er30 (Bitwise.and er32 (Bitwise.xor er31 er30)) + 0x2E1B2138 + w33

        t2r33 =
            bsig0 ar32 + Bitwise.xor (Bitwise.xor (Bitwise.and ar32 ar31) (Bitwise.and ar32 ar30)) (Bitwise.and ar31 ar30)

        ar33 =
            t1r33 + t2r33

        er33 =
            ar29 + t1r33

        -- Round 34
        t1r34 =
            er30 + bsig1 er33 + Bitwise.xor er31 (Bitwise.and er33 (Bitwise.xor er32 er31)) + 0x4D2C6DFC + w34

        t2r34 =
            bsig0 ar33 + Bitwise.xor (Bitwise.xor (Bitwise.and ar33 ar32) (Bitwise.and ar33 ar31)) (Bitwise.and ar32 ar31)

        ar34 =
            t1r34 + t2r34

        er34 =
            ar30 + t1r34

        -- Round 35
        t1r35 =
            er31 + bsig1 er34 + Bitwise.xor er32 (Bitwise.and er34 (Bitwise.xor er33 er32)) + 0x53380D13 + w35

        t2r35 =
            bsig0 ar34 + Bitwise.xor (Bitwise.xor (Bitwise.and ar34 ar33) (Bitwise.and ar34 ar32)) (Bitwise.and ar33 ar32)

        ar35 =
            t1r35 + t2r35

        er35 =
            ar31 + t1r35

        -- Round 36
        t1r36 =
            er32 + bsig1 er35 + Bitwise.xor er33 (Bitwise.and er35 (Bitwise.xor er34 er33)) + 0x650A7354 + w36

        t2r36 =
            bsig0 ar35 + Bitwise.xor (Bitwise.xor (Bitwise.and ar35 ar34) (Bitwise.and ar35 ar33)) (Bitwise.and ar34 ar33)

        ar36 =
            t1r36 + t2r36

        er36 =
            ar32 + t1r36

        -- Round 37
        t1r37 =
            er33 + bsig1 er36 + Bitwise.xor er34 (Bitwise.and er36 (Bitwise.xor er35 er34)) + 0x766A0ABB + w37

        t2r37 =
            bsig0 ar36 + Bitwise.xor (Bitwise.xor (Bitwise.and ar36 ar35) (Bitwise.and ar36 ar34)) (Bitwise.and ar35 ar34)

        ar37 =
            t1r37 + t2r37

        er37 =
            ar33 + t1r37

        -- Round 38
        t1r38 =
            er34 + bsig1 er37 + Bitwise.xor er35 (Bitwise.and er37 (Bitwise.xor er36 er35)) + 0x81C2C92E + w38

        t2r38 =
            bsig0 ar37 + Bitwise.xor (Bitwise.xor (Bitwise.and ar37 ar36) (Bitwise.and ar37 ar35)) (Bitwise.and ar36 ar35)

        ar38 =
            t1r38 + t2r38

        er38 =
            ar34 + t1r38

        -- Round 39
        t1r39 =
            er35 + bsig1 er38 + Bitwise.xor er36 (Bitwise.and er38 (Bitwise.xor er37 er36)) + 0x92722C85 + w39

        t2r39 =
            bsig0 ar38 + Bitwise.xor (Bitwise.xor (Bitwise.and ar38 ar37) (Bitwise.and ar38 ar36)) (Bitwise.and ar37 ar36)

        ar39 =
            t1r39 + t2r39

        er39 =
            ar35 + t1r39

        -- Round 40
        t1r40 =
            er36 + bsig1 er39 + Bitwise.xor er37 (Bitwise.and er39 (Bitwise.xor er38 er37)) + 0xA2BFE8A1 + w40

        t2r40 =
            bsig0 ar39 + Bitwise.xor (Bitwise.xor (Bitwise.and ar39 ar38) (Bitwise.and ar39 ar37)) (Bitwise.and ar38 ar37)

        ar40 =
            t1r40 + t2r40

        er40 =
            ar36 + t1r40

        -- Round 41
        t1r41 =
            er37 + bsig1 er40 + Bitwise.xor er38 (Bitwise.and er40 (Bitwise.xor er39 er38)) + 0xA81A664B + w41

        t2r41 =
            bsig0 ar40 + Bitwise.xor (Bitwise.xor (Bitwise.and ar40 ar39) (Bitwise.and ar40 ar38)) (Bitwise.and ar39 ar38)

        ar41 =
            t1r41 + t2r41

        er41 =
            ar37 + t1r41

        -- Round 42
        t1r42 =
            er38 + bsig1 er41 + Bitwise.xor er39 (Bitwise.and er41 (Bitwise.xor er40 er39)) + 0xC24B8B70 + w42

        t2r42 =
            bsig0 ar41 + Bitwise.xor (Bitwise.xor (Bitwise.and ar41 ar40) (Bitwise.and ar41 ar39)) (Bitwise.and ar40 ar39)

        ar42 =
            t1r42 + t2r42

        er42 =
            ar38 + t1r42

        -- Round 43
        t1r43 =
            er39 + bsig1 er42 + Bitwise.xor er40 (Bitwise.and er42 (Bitwise.xor er41 er40)) + 0xC76C51A3 + w43

        t2r43 =
            bsig0 ar42 + Bitwise.xor (Bitwise.xor (Bitwise.and ar42 ar41) (Bitwise.and ar42 ar40)) (Bitwise.and ar41 ar40)

        ar43 =
            t1r43 + t2r43

        er43 =
            ar39 + t1r43

        -- Round 44
        t1r44 =
            er40 + bsig1 er43 + Bitwise.xor er41 (Bitwise.and er43 (Bitwise.xor er42 er41)) + 0xD192E819 + w44

        t2r44 =
            bsig0 ar43 + Bitwise.xor (Bitwise.xor (Bitwise.and ar43 ar42) (Bitwise.and ar43 ar41)) (Bitwise.and ar42 ar41)

        ar44 =
            t1r44 + t2r44

        er44 =
            ar40 + t1r44

        -- Round 45
        t1r45 =
            er41 + bsig1 er44 + Bitwise.xor er42 (Bitwise.and er44 (Bitwise.xor er43 er42)) + 0xD6990624 + w45

        t2r45 =
            bsig0 ar44 + Bitwise.xor (Bitwise.xor (Bitwise.and ar44 ar43) (Bitwise.and ar44 ar42)) (Bitwise.and ar43 ar42)

        ar45 =
            t1r45 + t2r45

        er45 =
            ar41 + t1r45

        -- Round 46
        t1r46 =
            er42 + bsig1 er45 + Bitwise.xor er43 (Bitwise.and er45 (Bitwise.xor er44 er43)) + 0xF40E3585 + w46

        t2r46 =
            bsig0 ar45 + Bitwise.xor (Bitwise.xor (Bitwise.and ar45 ar44) (Bitwise.and ar45 ar43)) (Bitwise.and ar44 ar43)

        ar46 =
            t1r46 + t2r46

        er46 =
            ar42 + t1r46

        -- Round 47
        t1r47 =
            er43 + bsig1 er46 + Bitwise.xor er44 (Bitwise.and er46 (Bitwise.xor er45 er44)) + 0x106AA070 + w47

        t2r47 =
            bsig0 ar46 + Bitwise.xor (Bitwise.xor (Bitwise.and ar46 ar45) (Bitwise.and ar46 ar44)) (Bitwise.and ar45 ar44)

        ar47 =
            t1r47 + t2r47

        er47 =
            ar43 + t1r47

        -- Round 48
        t1r48 =
            er44 + bsig1 er47 + Bitwise.xor er45 (Bitwise.and er47 (Bitwise.xor er46 er45)) + 0x19A4C116 + w48

        t2r48 =
            bsig0 ar47 + Bitwise.xor (Bitwise.xor (Bitwise.and ar47 ar46) (Bitwise.and ar47 ar45)) (Bitwise.and ar46 ar45)

        ar48 =
            t1r48 + t2r48

        er48 =
            ar44 + t1r48

        -- Round 49
        t1r49 =
            er45 + bsig1 er48 + Bitwise.xor er46 (Bitwise.and er48 (Bitwise.xor er47 er46)) + 0x1E376C08 + w49

        t2r49 =
            bsig0 ar48 + Bitwise.xor (Bitwise.xor (Bitwise.and ar48 ar47) (Bitwise.and ar48 ar46)) (Bitwise.and ar47 ar46)

        ar49 =
            t1r49 + t2r49

        er49 =
            ar45 + t1r49

        -- Round 50
        t1r50 =
            er46 + bsig1 er49 + Bitwise.xor er47 (Bitwise.and er49 (Bitwise.xor er48 er47)) + 0x2748774C + w50

        t2r50 =
            bsig0 ar49 + Bitwise.xor (Bitwise.xor (Bitwise.and ar49 ar48) (Bitwise.and ar49 ar47)) (Bitwise.and ar48 ar47)

        ar50 =
            t1r50 + t2r50

        er50 =
            ar46 + t1r50

        -- Round 51
        t1r51 =
            er47 + bsig1 er50 + Bitwise.xor er48 (Bitwise.and er50 (Bitwise.xor er49 er48)) + 0x34B0BCB5 + w51

        t2r51 =
            bsig0 ar50 + Bitwise.xor (Bitwise.xor (Bitwise.and ar50 ar49) (Bitwise.and ar50 ar48)) (Bitwise.and ar49 ar48)

        ar51 =
            t1r51 + t2r51

        er51 =
            ar47 + t1r51

        -- Round 52
        t1r52 =
            er48 + bsig1 er51 + Bitwise.xor er49 (Bitwise.and er51 (Bitwise.xor er50 er49)) + 0x391C0CB3 + w52

        t2r52 =
            bsig0 ar51 + Bitwise.xor (Bitwise.xor (Bitwise.and ar51 ar50) (Bitwise.and ar51 ar49)) (Bitwise.and ar50 ar49)

        ar52 =
            t1r52 + t2r52

        er52 =
            ar48 + t1r52

        -- Round 53
        t1r53 =
            er49 + bsig1 er52 + Bitwise.xor er50 (Bitwise.and er52 (Bitwise.xor er51 er50)) + 0x4ED8AA4A + w53

        t2r53 =
            bsig0 ar52 + Bitwise.xor (Bitwise.xor (Bitwise.and ar52 ar51) (Bitwise.and ar52 ar50)) (Bitwise.and ar51 ar50)

        ar53 =
            t1r53 + t2r53

        er53 =
            ar49 + t1r53

        -- Round 54
        t1r54 =
            er50 + bsig1 er53 + Bitwise.xor er51 (Bitwise.and er53 (Bitwise.xor er52 er51)) + 0x5B9CCA4F + w54

        t2r54 =
            bsig0 ar53 + Bitwise.xor (Bitwise.xor (Bitwise.and ar53 ar52) (Bitwise.and ar53 ar51)) (Bitwise.and ar52 ar51)

        ar54 =
            t1r54 + t2r54

        er54 =
            ar50 + t1r54

        -- Round 55
        t1r55 =
            er51 + bsig1 er54 + Bitwise.xor er52 (Bitwise.and er54 (Bitwise.xor er53 er52)) + 0x682E6FF3 + w55

        t2r55 =
            bsig0 ar54 + Bitwise.xor (Bitwise.xor (Bitwise.and ar54 ar53) (Bitwise.and ar54 ar52)) (Bitwise.and ar53 ar52)

        ar55 =
            t1r55 + t2r55

        er55 =
            ar51 + t1r55

        -- Round 56
        t1r56 =
            er52 + bsig1 er55 + Bitwise.xor er53 (Bitwise.and er55 (Bitwise.xor er54 er53)) + 0x748F82EE + w56

        t2r56 =
            bsig0 ar55 + Bitwise.xor (Bitwise.xor (Bitwise.and ar55 ar54) (Bitwise.and ar55 ar53)) (Bitwise.and ar54 ar53)

        ar56 =
            t1r56 + t2r56

        er56 =
            ar52 + t1r56

        -- Round 57
        t1r57 =
            er53 + bsig1 er56 + Bitwise.xor er54 (Bitwise.and er56 (Bitwise.xor er55 er54)) + 0x78A5636F + w57

        t2r57 =
            bsig0 ar56 + Bitwise.xor (Bitwise.xor (Bitwise.and ar56 ar55) (Bitwise.and ar56 ar54)) (Bitwise.and ar55 ar54)

        ar57 =
            t1r57 + t2r57

        er57 =
            ar53 + t1r57

        -- Round 58
        t1r58 =
            er54 + bsig1 er57 + Bitwise.xor er55 (Bitwise.and er57 (Bitwise.xor er56 er55)) + 0x84C87814 + w58

        t2r58 =
            bsig0 ar57 + Bitwise.xor (Bitwise.xor (Bitwise.and ar57 ar56) (Bitwise.and ar57 ar55)) (Bitwise.and ar56 ar55)

        ar58 =
            t1r58 + t2r58

        er58 =
            ar54 + t1r58

        -- Round 59
        t1r59 =
            er55 + bsig1 er58 + Bitwise.xor er56 (Bitwise.and er58 (Bitwise.xor er57 er56)) + 0x8CC70208 + w59

        t2r59 =
            bsig0 ar58 + Bitwise.xor (Bitwise.xor (Bitwise.and ar58 ar57) (Bitwise.and ar58 ar56)) (Bitwise.and ar57 ar56)

        ar59 =
            t1r59 + t2r59

        er59 =
            ar55 + t1r59

        -- Round 60
        t1r60 =
            er56 + bsig1 er59 + Bitwise.xor er57 (Bitwise.and er59 (Bitwise.xor er58 er57)) + 0x90BEFFFA + w60

        t2r60 =
            bsig0 ar59 + Bitwise.xor (Bitwise.xor (Bitwise.and ar59 ar58) (Bitwise.and ar59 ar57)) (Bitwise.and ar58 ar57)

        ar60 =
            t1r60 + t2r60

        er60 =
            ar56 + t1r60

        -- Round 61
        t1r61 =
            er57 + bsig1 er60 + Bitwise.xor er58 (Bitwise.and er60 (Bitwise.xor er59 er58)) + 0xA4506CEB + w61

        t2r61 =
            bsig0 ar60 + Bitwise.xor (Bitwise.xor (Bitwise.and ar60 ar59) (Bitwise.and ar60 ar58)) (Bitwise.and ar59 ar58)

        ar61 =
            t1r61 + t2r61

        er61 =
            ar57 + t1r61

        -- Round 62
        t1r62 =
            er58 + bsig1 er61 + Bitwise.xor er59 (Bitwise.and er61 (Bitwise.xor er60 er59)) + 0xBEF9A3F7 + w62

        t2r62 =
            bsig0 ar61 + Bitwise.xor (Bitwise.xor (Bitwise.and ar61 ar60) (Bitwise.and ar61 ar59)) (Bitwise.and ar60 ar59)

        ar62 =
            t1r62 + t2r62

        er62 =
            ar58 + t1r62

        -- Round 63
        t1r63 =
            er59 + bsig1 er62 + Bitwise.xor er60 (Bitwise.and er62 (Bitwise.xor er61 er60)) + 0xC67178F2 + w63

        t2r63 =
            bsig0 ar62 + Bitwise.xor (Bitwise.xor (Bitwise.and ar62 ar61) (Bitwise.and ar62 ar60)) (Bitwise.and ar61 ar60)

        ar63 =
            t1r63 + t2r63

        er63 =
            ar59 + t1r63
    in
    { h0 = h0 + ar63 |> unsigned
    , h1 = h1 + ar62 |> unsigned
    , h2 = h2 + ar61 |> unsigned
    , h3 = h3 + ar60 |> unsigned
    , h4 = h4 + er63 |> unsigned
    , h5 = h5 + er62 |> unsigned
    , h6 = h6 + er61 |> unsigned
    , h7 = h7 + er60 |> unsigned
    }



-- SHA-256 helper functions, all inlined as bitwise operations on 32-bit Ints


bsig0 : Int -> Int
bsig0 x =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 2 x) (Bitwise.shiftLeftBy 30 x))
            (Bitwise.or (Bitwise.shiftRightZfBy 13 x) (Bitwise.shiftLeftBy 19 x))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 22 x) (Bitwise.shiftLeftBy 10 x))


bsig1 : Int -> Int
bsig1 x =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 6 x) (Bitwise.shiftLeftBy 26 x))
            (Bitwise.or (Bitwise.shiftRightZfBy 11 x) (Bitwise.shiftLeftBy 21 x))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 25 x) (Bitwise.shiftLeftBy 7 x))


ssig0 : Int -> Int
ssig0 x =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 7 x) (Bitwise.shiftLeftBy 25 x))
            (Bitwise.or (Bitwise.shiftRightZfBy 18 x) (Bitwise.shiftLeftBy 14 x))
        )
        (Bitwise.shiftRightZfBy 3 x)


ssig1 : Int -> Int
ssig1 x =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 17 x) (Bitwise.shiftLeftBy 15 x))
            (Bitwise.or (Bitwise.shiftRightZfBy 19 x) (Bitwise.shiftLeftBy 13 x))
        )
        (Bitwise.shiftRightZfBy 10 x)






unsigned : Int -> Int
unsigned x =
    Bitwise.shiftRightZfBy 0 x



{-| Compute SHA-256 hash of bytes.
-}
hash : Bytes -> Bytes
hash bytes =
    fromBytes bytes |> toBytes


{-| Turn a digest into `Bytes`. The digest is stored as 8 big-endian 32-bit unsigned integers, so the width is 32 bytes or 256 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest s0 s1 s2 s3 s4 s5 s6 s7) =
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE s0
            , Encode.unsignedInt32 BE s1
            , Encode.unsignedInt32 BE s2
            , Encode.unsignedInt32 BE s3
            , Encode.unsignedInt32 BE s4
            , Encode.unsignedInt32 BE s5
            , Encode.unsignedInt32 BE s6
            , Encode.unsignedInt32 BE s7
            ]
        )
