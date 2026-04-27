module SHA256 exposing
    ( Digest
    , fromBytes
    , toBytes
    )

{-| [SHA-256] is a [cryptographic hash function] that gives 128 bits of security.

[SHA-256]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromBytes


# To binary data

@docs toBytes

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
            ssig1 w14 + w9 + ssig0 w1 + w0 |> unsigned

        w17 =
            ssig1 w15 + w10 + ssig0 w2 + w1 |> unsigned

        w18 =
            ssig1 w16 + w11 + ssig0 w3 + w2 |> unsigned

        w19 =
            ssig1 w17 + w12 + ssig0 w4 + w3 |> unsigned

        w20 =
            ssig1 w18 + w13 + ssig0 w5 + w4 |> unsigned

        w21 =
            ssig1 w19 + w14 + ssig0 w6 + w5 |> unsigned

        w22 =
            ssig1 w20 + w15 + ssig0 w7 + w6 |> unsigned

        w23 =
            ssig1 w21 + w16 + ssig0 w8 + w7 |> unsigned

        w24 =
            ssig1 w22 + w17 + ssig0 w9 + w8 |> unsigned

        w25 =
            ssig1 w23 + w18 + ssig0 w10 + w9 |> unsigned

        w26 =
            ssig1 w24 + w19 + ssig0 w11 + w10 |> unsigned

        w27 =
            ssig1 w25 + w20 + ssig0 w12 + w11 |> unsigned

        w28 =
            ssig1 w26 + w21 + ssig0 w13 + w12 |> unsigned

        w29 =
            ssig1 w27 + w22 + ssig0 w14 + w13 |> unsigned

        w30 =
            ssig1 w28 + w23 + ssig0 w15 + w14 |> unsigned

        w31 =
            ssig1 w29 + w24 + ssig0 w16 + w15 |> unsigned

        w32 =
            ssig1 w30 + w25 + ssig0 w17 + w16 |> unsigned

        w33 =
            ssig1 w31 + w26 + ssig0 w18 + w17 |> unsigned

        w34 =
            ssig1 w32 + w27 + ssig0 w19 + w18 |> unsigned

        w35 =
            ssig1 w33 + w28 + ssig0 w20 + w19 |> unsigned

        w36 =
            ssig1 w34 + w29 + ssig0 w21 + w20 |> unsigned

        w37 =
            ssig1 w35 + w30 + ssig0 w22 + w21 |> unsigned

        w38 =
            ssig1 w36 + w31 + ssig0 w23 + w22 |> unsigned

        w39 =
            ssig1 w37 + w32 + ssig0 w24 + w23 |> unsigned

        w40 =
            ssig1 w38 + w33 + ssig0 w25 + w24 |> unsigned

        w41 =
            ssig1 w39 + w34 + ssig0 w26 + w25 |> unsigned

        w42 =
            ssig1 w40 + w35 + ssig0 w27 + w26 |> unsigned

        w43 =
            ssig1 w41 + w36 + ssig0 w28 + w27 |> unsigned

        w44 =
            ssig1 w42 + w37 + ssig0 w29 + w28 |> unsigned

        w45 =
            ssig1 w43 + w38 + ssig0 w30 + w29 |> unsigned

        w46 =
            ssig1 w44 + w39 + ssig0 w31 + w30 |> unsigned

        w47 =
            ssig1 w45 + w40 + ssig0 w32 + w31 |> unsigned

        w48 =
            ssig1 w46 + w41 + ssig0 w33 + w32 |> unsigned

        w49 =
            ssig1 w47 + w42 + ssig0 w34 + w33 |> unsigned

        w50 =
            ssig1 w48 + w43 + ssig0 w35 + w34 |> unsigned

        w51 =
            ssig1 w49 + w44 + ssig0 w36 + w35 |> unsigned

        w52 =
            ssig1 w50 + w45 + ssig0 w37 + w36 |> unsigned

        w53 =
            ssig1 w51 + w46 + ssig0 w38 + w37 |> unsigned

        w54 =
            ssig1 w52 + w47 + ssig0 w39 + w38 |> unsigned

        w55 =
            ssig1 w53 + w48 + ssig0 w40 + w39 |> unsigned

        w56 =
            ssig1 w54 + w49 + ssig0 w41 + w40 |> unsigned

        w57 =
            ssig1 w55 + w50 + ssig0 w42 + w41 |> unsigned

        w58 =
            ssig1 w56 + w51 + ssig0 w43 + w42 |> unsigned

        w59 =
            ssig1 w57 + w52 + ssig0 w44 + w43 |> unsigned

        w60 =
            ssig1 w58 + w53 + ssig0 w45 + w44 |> unsigned

        w61 =
            ssig1 w59 + w54 + ssig0 w46 + w45 |> unsigned

        w62 =
            ssig1 w60 + w55 + ssig0 w47 + w46 |> unsigned

        w63 =
            ssig1 w61 + w56 + ssig0 w48 + w47 |> unsigned

        -- 64 compression rounds, fully unrolled with inlined round constants.
        -- We track only a (arN) and e (erN); b,c,d are previous a's; f,g,h are previous e's.
        -- Round 0
        t1r0 =
            h7 + bsig1 h4 + ch h4 h5 h6 + 0x428A2F98 + w0 |> unsigned

        t2r0 =
            bsig0 h0 + maj h0 h1 h2 |> unsigned

        ar0 =
            t1r0 + t2r0 |> unsigned

        er0 =
            h3 + t1r0 |> unsigned

        -- Round 1
        t1r1 =
            h6 + bsig1 er0 + ch er0 h4 h5 + 0x71374491 + w1 |> unsigned

        t2r1 =
            bsig0 ar0 + maj ar0 h0 h1 |> unsigned

        ar1 =
            t1r1 + t2r1 |> unsigned

        er1 =
            h2 + t1r1 |> unsigned

        -- Round 2
        t1r2 =
            h5 + bsig1 er1 + ch er1 er0 h4 + 0xB5C0FBCF + w2 |> unsigned

        t2r2 =
            bsig0 ar1 + maj ar1 ar0 h0 |> unsigned

        ar2 =
            t1r2 + t2r2 |> unsigned

        er2 =
            h1 + t1r2 |> unsigned

        -- Round 3
        t1r3 =
            h4 + bsig1 er2 + ch er2 er1 er0 + 0xE9B5DBA5 + w3 |> unsigned

        t2r3 =
            bsig0 ar2 + maj ar2 ar1 ar0 |> unsigned

        ar3 =
            t1r3 + t2r3 |> unsigned

        er3 =
            h0 + t1r3 |> unsigned

        -- Round 4
        t1r4 =
            er0 + bsig1 er3 + ch er3 er2 er1 + 0x3956C25B + w4 |> unsigned

        t2r4 =
            bsig0 ar3 + maj ar3 ar2 ar1 |> unsigned

        ar4 =
            t1r4 + t2r4 |> unsigned

        er4 =
            ar0 + t1r4 |> unsigned

        -- Round 5
        t1r5 =
            er1 + bsig1 er4 + ch er4 er3 er2 + 0x59F111F1 + w5 |> unsigned

        t2r5 =
            bsig0 ar4 + maj ar4 ar3 ar2 |> unsigned

        ar5 =
            t1r5 + t2r5 |> unsigned

        er5 =
            ar1 + t1r5 |> unsigned

        -- Round 6
        t1r6 =
            er2 + bsig1 er5 + ch er5 er4 er3 + 0x923F82A4 + w6 |> unsigned

        t2r6 =
            bsig0 ar5 + maj ar5 ar4 ar3 |> unsigned

        ar6 =
            t1r6 + t2r6 |> unsigned

        er6 =
            ar2 + t1r6 |> unsigned

        -- Round 7
        t1r7 =
            er3 + bsig1 er6 + ch er6 er5 er4 + 0xAB1C5ED5 + w7 |> unsigned

        t2r7 =
            bsig0 ar6 + maj ar6 ar5 ar4 |> unsigned

        ar7 =
            t1r7 + t2r7 |> unsigned

        er7 =
            ar3 + t1r7 |> unsigned

        -- Round 8
        t1r8 =
            er4 + bsig1 er7 + ch er7 er6 er5 + 0xD807AA98 + w8 |> unsigned

        t2r8 =
            bsig0 ar7 + maj ar7 ar6 ar5 |> unsigned

        ar8 =
            t1r8 + t2r8 |> unsigned

        er8 =
            ar4 + t1r8 |> unsigned

        -- Round 9
        t1r9 =
            er5 + bsig1 er8 + ch er8 er7 er6 + 0x12835B01 + w9 |> unsigned

        t2r9 =
            bsig0 ar8 + maj ar8 ar7 ar6 |> unsigned

        ar9 =
            t1r9 + t2r9 |> unsigned

        er9 =
            ar5 + t1r9 |> unsigned

        -- Round 10
        t1r10 =
            er6 + bsig1 er9 + ch er9 er8 er7 + 0x243185BE + w10 |> unsigned

        t2r10 =
            bsig0 ar9 + maj ar9 ar8 ar7 |> unsigned

        ar10 =
            t1r10 + t2r10 |> unsigned

        er10 =
            ar6 + t1r10 |> unsigned

        -- Round 11
        t1r11 =
            er7 + bsig1 er10 + ch er10 er9 er8 + 0x550C7DC3 + w11 |> unsigned

        t2r11 =
            bsig0 ar10 + maj ar10 ar9 ar8 |> unsigned

        ar11 =
            t1r11 + t2r11 |> unsigned

        er11 =
            ar7 + t1r11 |> unsigned

        -- Round 12
        t1r12 =
            er8 + bsig1 er11 + ch er11 er10 er9 + 0x72BE5D74 + w12 |> unsigned

        t2r12 =
            bsig0 ar11 + maj ar11 ar10 ar9 |> unsigned

        ar12 =
            t1r12 + t2r12 |> unsigned

        er12 =
            ar8 + t1r12 |> unsigned

        -- Round 13
        t1r13 =
            er9 + bsig1 er12 + ch er12 er11 er10 + 0x80DEB1FE + w13 |> unsigned

        t2r13 =
            bsig0 ar12 + maj ar12 ar11 ar10 |> unsigned

        ar13 =
            t1r13 + t2r13 |> unsigned

        er13 =
            ar9 + t1r13 |> unsigned

        -- Round 14
        t1r14 =
            er10 + bsig1 er13 + ch er13 er12 er11 + 0x9BDC06A7 + w14 |> unsigned

        t2r14 =
            bsig0 ar13 + maj ar13 ar12 ar11 |> unsigned

        ar14 =
            t1r14 + t2r14 |> unsigned

        er14 =
            ar10 + t1r14 |> unsigned

        -- Round 15
        t1r15 =
            er11 + bsig1 er14 + ch er14 er13 er12 + 0xC19BF174 + w15 |> unsigned

        t2r15 =
            bsig0 ar14 + maj ar14 ar13 ar12 |> unsigned

        ar15 =
            t1r15 + t2r15 |> unsigned

        er15 =
            ar11 + t1r15 |> unsigned

        -- Round 16
        t1r16 =
            er12 + bsig1 er15 + ch er15 er14 er13 + 0xE49B69C1 + w16 |> unsigned

        t2r16 =
            bsig0 ar15 + maj ar15 ar14 ar13 |> unsigned

        ar16 =
            t1r16 + t2r16 |> unsigned

        er16 =
            ar12 + t1r16 |> unsigned

        -- Round 17
        t1r17 =
            er13 + bsig1 er16 + ch er16 er15 er14 + 0xEFBE4786 + w17 |> unsigned

        t2r17 =
            bsig0 ar16 + maj ar16 ar15 ar14 |> unsigned

        ar17 =
            t1r17 + t2r17 |> unsigned

        er17 =
            ar13 + t1r17 |> unsigned

        -- Round 18
        t1r18 =
            er14 + bsig1 er17 + ch er17 er16 er15 + 0x0FC19DC6 + w18 |> unsigned

        t2r18 =
            bsig0 ar17 + maj ar17 ar16 ar15 |> unsigned

        ar18 =
            t1r18 + t2r18 |> unsigned

        er18 =
            ar14 + t1r18 |> unsigned

        -- Round 19
        t1r19 =
            er15 + bsig1 er18 + ch er18 er17 er16 + 0x240CA1CC + w19 |> unsigned

        t2r19 =
            bsig0 ar18 + maj ar18 ar17 ar16 |> unsigned

        ar19 =
            t1r19 + t2r19 |> unsigned

        er19 =
            ar15 + t1r19 |> unsigned

        -- Round 20
        t1r20 =
            er16 + bsig1 er19 + ch er19 er18 er17 + 0x2DE92C6F + w20 |> unsigned

        t2r20 =
            bsig0 ar19 + maj ar19 ar18 ar17 |> unsigned

        ar20 =
            t1r20 + t2r20 |> unsigned

        er20 =
            ar16 + t1r20 |> unsigned

        -- Round 21
        t1r21 =
            er17 + bsig1 er20 + ch er20 er19 er18 + 0x4A7484AA + w21 |> unsigned

        t2r21 =
            bsig0 ar20 + maj ar20 ar19 ar18 |> unsigned

        ar21 =
            t1r21 + t2r21 |> unsigned

        er21 =
            ar17 + t1r21 |> unsigned

        -- Round 22
        t1r22 =
            er18 + bsig1 er21 + ch er21 er20 er19 + 0x5CB0A9DC + w22 |> unsigned

        t2r22 =
            bsig0 ar21 + maj ar21 ar20 ar19 |> unsigned

        ar22 =
            t1r22 + t2r22 |> unsigned

        er22 =
            ar18 + t1r22 |> unsigned

        -- Round 23
        t1r23 =
            er19 + bsig1 er22 + ch er22 er21 er20 + 0x76F988DA + w23 |> unsigned

        t2r23 =
            bsig0 ar22 + maj ar22 ar21 ar20 |> unsigned

        ar23 =
            t1r23 + t2r23 |> unsigned

        er23 =
            ar19 + t1r23 |> unsigned

        -- Round 24
        t1r24 =
            er20 + bsig1 er23 + ch er23 er22 er21 + 0x983E5152 + w24 |> unsigned

        t2r24 =
            bsig0 ar23 + maj ar23 ar22 ar21 |> unsigned

        ar24 =
            t1r24 + t2r24 |> unsigned

        er24 =
            ar20 + t1r24 |> unsigned

        -- Round 25
        t1r25 =
            er21 + bsig1 er24 + ch er24 er23 er22 + 0xA831C66D + w25 |> unsigned

        t2r25 =
            bsig0 ar24 + maj ar24 ar23 ar22 |> unsigned

        ar25 =
            t1r25 + t2r25 |> unsigned

        er25 =
            ar21 + t1r25 |> unsigned

        -- Round 26
        t1r26 =
            er22 + bsig1 er25 + ch er25 er24 er23 + 0xB00327C8 + w26 |> unsigned

        t2r26 =
            bsig0 ar25 + maj ar25 ar24 ar23 |> unsigned

        ar26 =
            t1r26 + t2r26 |> unsigned

        er26 =
            ar22 + t1r26 |> unsigned

        -- Round 27
        t1r27 =
            er23 + bsig1 er26 + ch er26 er25 er24 + 0xBF597FC7 + w27 |> unsigned

        t2r27 =
            bsig0 ar26 + maj ar26 ar25 ar24 |> unsigned

        ar27 =
            t1r27 + t2r27 |> unsigned

        er27 =
            ar23 + t1r27 |> unsigned

        -- Round 28
        t1r28 =
            er24 + bsig1 er27 + ch er27 er26 er25 + 0xC6E00BF3 + w28 |> unsigned

        t2r28 =
            bsig0 ar27 + maj ar27 ar26 ar25 |> unsigned

        ar28 =
            t1r28 + t2r28 |> unsigned

        er28 =
            ar24 + t1r28 |> unsigned

        -- Round 29
        t1r29 =
            er25 + bsig1 er28 + ch er28 er27 er26 + 0xD5A79147 + w29 |> unsigned

        t2r29 =
            bsig0 ar28 + maj ar28 ar27 ar26 |> unsigned

        ar29 =
            t1r29 + t2r29 |> unsigned

        er29 =
            ar25 + t1r29 |> unsigned

        -- Round 30
        t1r30 =
            er26 + bsig1 er29 + ch er29 er28 er27 + 0x06CA6351 + w30 |> unsigned

        t2r30 =
            bsig0 ar29 + maj ar29 ar28 ar27 |> unsigned

        ar30 =
            t1r30 + t2r30 |> unsigned

        er30 =
            ar26 + t1r30 |> unsigned

        -- Round 31
        t1r31 =
            er27 + bsig1 er30 + ch er30 er29 er28 + 0x14292967 + w31 |> unsigned

        t2r31 =
            bsig0 ar30 + maj ar30 ar29 ar28 |> unsigned

        ar31 =
            t1r31 + t2r31 |> unsigned

        er31 =
            ar27 + t1r31 |> unsigned

        -- Round 32
        t1r32 =
            er28 + bsig1 er31 + ch er31 er30 er29 + 0x27B70A85 + w32 |> unsigned

        t2r32 =
            bsig0 ar31 + maj ar31 ar30 ar29 |> unsigned

        ar32 =
            t1r32 + t2r32 |> unsigned

        er32 =
            ar28 + t1r32 |> unsigned

        -- Round 33
        t1r33 =
            er29 + bsig1 er32 + ch er32 er31 er30 + 0x2E1B2138 + w33 |> unsigned

        t2r33 =
            bsig0 ar32 + maj ar32 ar31 ar30 |> unsigned

        ar33 =
            t1r33 + t2r33 |> unsigned

        er33 =
            ar29 + t1r33 |> unsigned

        -- Round 34
        t1r34 =
            er30 + bsig1 er33 + ch er33 er32 er31 + 0x4D2C6DFC + w34 |> unsigned

        t2r34 =
            bsig0 ar33 + maj ar33 ar32 ar31 |> unsigned

        ar34 =
            t1r34 + t2r34 |> unsigned

        er34 =
            ar30 + t1r34 |> unsigned

        -- Round 35
        t1r35 =
            er31 + bsig1 er34 + ch er34 er33 er32 + 0x53380D13 + w35 |> unsigned

        t2r35 =
            bsig0 ar34 + maj ar34 ar33 ar32 |> unsigned

        ar35 =
            t1r35 + t2r35 |> unsigned

        er35 =
            ar31 + t1r35 |> unsigned

        -- Round 36
        t1r36 =
            er32 + bsig1 er35 + ch er35 er34 er33 + 0x650A7354 + w36 |> unsigned

        t2r36 =
            bsig0 ar35 + maj ar35 ar34 ar33 |> unsigned

        ar36 =
            t1r36 + t2r36 |> unsigned

        er36 =
            ar32 + t1r36 |> unsigned

        -- Round 37
        t1r37 =
            er33 + bsig1 er36 + ch er36 er35 er34 + 0x766A0ABB + w37 |> unsigned

        t2r37 =
            bsig0 ar36 + maj ar36 ar35 ar34 |> unsigned

        ar37 =
            t1r37 + t2r37 |> unsigned

        er37 =
            ar33 + t1r37 |> unsigned

        -- Round 38
        t1r38 =
            er34 + bsig1 er37 + ch er37 er36 er35 + 0x81C2C92E + w38 |> unsigned

        t2r38 =
            bsig0 ar37 + maj ar37 ar36 ar35 |> unsigned

        ar38 =
            t1r38 + t2r38 |> unsigned

        er38 =
            ar34 + t1r38 |> unsigned

        -- Round 39
        t1r39 =
            er35 + bsig1 er38 + ch er38 er37 er36 + 0x92722C85 + w39 |> unsigned

        t2r39 =
            bsig0 ar38 + maj ar38 ar37 ar36 |> unsigned

        ar39 =
            t1r39 + t2r39 |> unsigned

        er39 =
            ar35 + t1r39 |> unsigned

        -- Round 40
        t1r40 =
            er36 + bsig1 er39 + ch er39 er38 er37 + 0xA2BFE8A1 + w40 |> unsigned

        t2r40 =
            bsig0 ar39 + maj ar39 ar38 ar37 |> unsigned

        ar40 =
            t1r40 + t2r40 |> unsigned

        er40 =
            ar36 + t1r40 |> unsigned

        -- Round 41
        t1r41 =
            er37 + bsig1 er40 + ch er40 er39 er38 + 0xA81A664B + w41 |> unsigned

        t2r41 =
            bsig0 ar40 + maj ar40 ar39 ar38 |> unsigned

        ar41 =
            t1r41 + t2r41 |> unsigned

        er41 =
            ar37 + t1r41 |> unsigned

        -- Round 42
        t1r42 =
            er38 + bsig1 er41 + ch er41 er40 er39 + 0xC24B8B70 + w42 |> unsigned

        t2r42 =
            bsig0 ar41 + maj ar41 ar40 ar39 |> unsigned

        ar42 =
            t1r42 + t2r42 |> unsigned

        er42 =
            ar38 + t1r42 |> unsigned

        -- Round 43
        t1r43 =
            er39 + bsig1 er42 + ch er42 er41 er40 + 0xC76C51A3 + w43 |> unsigned

        t2r43 =
            bsig0 ar42 + maj ar42 ar41 ar40 |> unsigned

        ar43 =
            t1r43 + t2r43 |> unsigned

        er43 =
            ar39 + t1r43 |> unsigned

        -- Round 44
        t1r44 =
            er40 + bsig1 er43 + ch er43 er42 er41 + 0xD192E819 + w44 |> unsigned

        t2r44 =
            bsig0 ar43 + maj ar43 ar42 ar41 |> unsigned

        ar44 =
            t1r44 + t2r44 |> unsigned

        er44 =
            ar40 + t1r44 |> unsigned

        -- Round 45
        t1r45 =
            er41 + bsig1 er44 + ch er44 er43 er42 + 0xD6990624 + w45 |> unsigned

        t2r45 =
            bsig0 ar44 + maj ar44 ar43 ar42 |> unsigned

        ar45 =
            t1r45 + t2r45 |> unsigned

        er45 =
            ar41 + t1r45 |> unsigned

        -- Round 46
        t1r46 =
            er42 + bsig1 er45 + ch er45 er44 er43 + 0xF40E3585 + w46 |> unsigned

        t2r46 =
            bsig0 ar45 + maj ar45 ar44 ar43 |> unsigned

        ar46 =
            t1r46 + t2r46 |> unsigned

        er46 =
            ar42 + t1r46 |> unsigned

        -- Round 47
        t1r47 =
            er43 + bsig1 er46 + ch er46 er45 er44 + 0x106AA070 + w47 |> unsigned

        t2r47 =
            bsig0 ar46 + maj ar46 ar45 ar44 |> unsigned

        ar47 =
            t1r47 + t2r47 |> unsigned

        er47 =
            ar43 + t1r47 |> unsigned

        -- Round 48
        t1r48 =
            er44 + bsig1 er47 + ch er47 er46 er45 + 0x19A4C116 + w48 |> unsigned

        t2r48 =
            bsig0 ar47 + maj ar47 ar46 ar45 |> unsigned

        ar48 =
            t1r48 + t2r48 |> unsigned

        er48 =
            ar44 + t1r48 |> unsigned

        -- Round 49
        t1r49 =
            er45 + bsig1 er48 + ch er48 er47 er46 + 0x1E376C08 + w49 |> unsigned

        t2r49 =
            bsig0 ar48 + maj ar48 ar47 ar46 |> unsigned

        ar49 =
            t1r49 + t2r49 |> unsigned

        er49 =
            ar45 + t1r49 |> unsigned

        -- Round 50
        t1r50 =
            er46 + bsig1 er49 + ch er49 er48 er47 + 0x2748774C + w50 |> unsigned

        t2r50 =
            bsig0 ar49 + maj ar49 ar48 ar47 |> unsigned

        ar50 =
            t1r50 + t2r50 |> unsigned

        er50 =
            ar46 + t1r50 |> unsigned

        -- Round 51
        t1r51 =
            er47 + bsig1 er50 + ch er50 er49 er48 + 0x34B0BCB5 + w51 |> unsigned

        t2r51 =
            bsig0 ar50 + maj ar50 ar49 ar48 |> unsigned

        ar51 =
            t1r51 + t2r51 |> unsigned

        er51 =
            ar47 + t1r51 |> unsigned

        -- Round 52
        t1r52 =
            er48 + bsig1 er51 + ch er51 er50 er49 + 0x391C0CB3 + w52 |> unsigned

        t2r52 =
            bsig0 ar51 + maj ar51 ar50 ar49 |> unsigned

        ar52 =
            t1r52 + t2r52 |> unsigned

        er52 =
            ar48 + t1r52 |> unsigned

        -- Round 53
        t1r53 =
            er49 + bsig1 er52 + ch er52 er51 er50 + 0x4ED8AA4A + w53 |> unsigned

        t2r53 =
            bsig0 ar52 + maj ar52 ar51 ar50 |> unsigned

        ar53 =
            t1r53 + t2r53 |> unsigned

        er53 =
            ar49 + t1r53 |> unsigned

        -- Round 54
        t1r54 =
            er50 + bsig1 er53 + ch er53 er52 er51 + 0x5B9CCA4F + w54 |> unsigned

        t2r54 =
            bsig0 ar53 + maj ar53 ar52 ar51 |> unsigned

        ar54 =
            t1r54 + t2r54 |> unsigned

        er54 =
            ar50 + t1r54 |> unsigned

        -- Round 55
        t1r55 =
            er51 + bsig1 er54 + ch er54 er53 er52 + 0x682E6FF3 + w55 |> unsigned

        t2r55 =
            bsig0 ar54 + maj ar54 ar53 ar52 |> unsigned

        ar55 =
            t1r55 + t2r55 |> unsigned

        er55 =
            ar51 + t1r55 |> unsigned

        -- Round 56
        t1r56 =
            er52 + bsig1 er55 + ch er55 er54 er53 + 0x748F82EE + w56 |> unsigned

        t2r56 =
            bsig0 ar55 + maj ar55 ar54 ar53 |> unsigned

        ar56 =
            t1r56 + t2r56 |> unsigned

        er56 =
            ar52 + t1r56 |> unsigned

        -- Round 57
        t1r57 =
            er53 + bsig1 er56 + ch er56 er55 er54 + 0x78A5636F + w57 |> unsigned

        t2r57 =
            bsig0 ar56 + maj ar56 ar55 ar54 |> unsigned

        ar57 =
            t1r57 + t2r57 |> unsigned

        er57 =
            ar53 + t1r57 |> unsigned

        -- Round 58
        t1r58 =
            er54 + bsig1 er57 + ch er57 er56 er55 + 0x84C87814 + w58 |> unsigned

        t2r58 =
            bsig0 ar57 + maj ar57 ar56 ar55 |> unsigned

        ar58 =
            t1r58 + t2r58 |> unsigned

        er58 =
            ar54 + t1r58 |> unsigned

        -- Round 59
        t1r59 =
            er55 + bsig1 er58 + ch er58 er57 er56 + 0x8CC70208 + w59 |> unsigned

        t2r59 =
            bsig0 ar58 + maj ar58 ar57 ar56 |> unsigned

        ar59 =
            t1r59 + t2r59 |> unsigned

        er59 =
            ar55 + t1r59 |> unsigned

        -- Round 60
        t1r60 =
            er56 + bsig1 er59 + ch er59 er58 er57 + 0x90BEFFFA + w60 |> unsigned

        t2r60 =
            bsig0 ar59 + maj ar59 ar58 ar57 |> unsigned

        ar60 =
            t1r60 + t2r60 |> unsigned

        er60 =
            ar56 + t1r60 |> unsigned

        -- Round 61
        t1r61 =
            er57 + bsig1 er60 + ch er60 er59 er58 + 0xA4506CEB + w61 |> unsigned

        t2r61 =
            bsig0 ar60 + maj ar60 ar59 ar58 |> unsigned

        ar61 =
            t1r61 + t2r61 |> unsigned

        er61 =
            ar57 + t1r61 |> unsigned

        -- Round 62
        t1r62 =
            er58 + bsig1 er61 + ch er61 er60 er59 + 0xBEF9A3F7 + w62 |> unsigned

        t2r62 =
            bsig0 ar61 + maj ar61 ar60 ar59 |> unsigned

        ar62 =
            t1r62 + t2r62 |> unsigned

        er62 =
            ar58 + t1r62 |> unsigned

        -- Round 63
        t1r63 =
            er59 + bsig1 er62 + ch er62 er61 er60 + 0xC67178F2 + w63 |> unsigned

        t2r63 =
            bsig0 ar62 + maj ar62 ar61 ar60 |> unsigned

        ar63 =
            t1r63 + t2r63 |> unsigned

        er63 =
            ar59 + t1r63 |> unsigned
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


ch : Int -> Int -> Int -> Int
ch x y z =
    Bitwise.xor z (Bitwise.and x (Bitwise.xor y z))


maj : Int -> Int -> Int -> Int
maj x y z =
    Bitwise.xor (Bitwise.xor (Bitwise.and x y) (Bitwise.and x z)) (Bitwise.and y z)


unsigned : Int -> Int
unsigned x =
    Bitwise.shiftRightZfBy 0 x


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
