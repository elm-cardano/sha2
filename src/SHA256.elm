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


{-| Decode 8 big-endian u32 words. Inner map5 decodes 5 words and returns an F3
closure; outer map4 feeds the remaining 3 words via A3 fast-path. No tuples.
-}
halfBlockDecoder : Decoder HalfBlock
halfBlockDecoder =
    Decode.map4 (\partial f g h -> partial f g h)
        (Decode.map5 (\a b c d e -> \f g h -> HalfBlock a b c d e f g h) u32 u32 u32 u32 u32)
        u32
        u32
        u32


u32 : Decoder Int
u32 =
    Decode.unsignedInt32 BE


type alias RoundState =
    { a : Int
    , b : Int
    , c : Int
    , d : Int
    , e : Int
    , f : Int
    , g : Int
    , h : Int
    }


{-| Execute two SHA-256 compression rounds. F5 function (within Elm's fast-call path).
Takes two (k, w) pairs and the current 8-word working state.
-}
twoRounds : Int -> Int -> Int -> Int -> RoundState -> RoundState
twoRounds k0 w0 k1 w1 s =
    let
        -- First round
        t1a =
            s.h + bsig1 s.e + Bitwise.xor s.g (Bitwise.and s.e (Bitwise.xor s.f s.g)) + k0 + w0

        t2a =
            bsig0 s.a + Bitwise.xor (Bitwise.xor (Bitwise.and s.a s.b) (Bitwise.and s.a s.c)) (Bitwise.and s.b s.c)

        a1 =
            t1a + t2a

        e1 =
            s.d + t1a

        -- Second round
        t1b =
            s.g + bsig1 e1 + Bitwise.xor s.f (Bitwise.and e1 (Bitwise.xor s.e s.f)) + k1 + w1

        t2b =
            bsig0 a1 + Bitwise.xor (Bitwise.xor (Bitwise.and a1 s.a) (Bitwise.and a1 s.b)) (Bitwise.and s.a s.b)

        a2 =
            t1b + t2b

        e2 =
            s.c + t1b
    in
    { a = a2, b = a1, c = s.a, d = s.b, e = e2, f = e1, g = s.e, h = s.f }


{-| SHA-256 compression function. Takes the current hash state and 16 message words
(as two HalfBlocks), expands the message schedule and runs all 64 rounds via twoRounds.
-}
compress : BlockState -> HalfBlock -> HalfBlock -> { h0 : Int, h1 : Int, h2 : Int, h3 : Int, h4 : Int, h5 : Int, h6 : Int, h7 : Int }
compress state first second =
    let
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

        -- Initial round state
        s0 =
            { a = state.h0, b = state.h1, c = state.h2, d = state.h3, e = state.h4, f = state.h5, g = state.h6, h = state.h7 }

        -- 32 calls to twoRounds (64 rounds total)
        s1 =
            twoRounds 0x428A2F98 w0 0x71374491 w1 s0

        s2 =
            twoRounds 0xB5C0FBCF w2 0xE9B5DBA5 w3 s1

        s3 =
            twoRounds 0x3956C25B w4 0x59F111F1 w5 s2

        s4 =
            twoRounds 0x923F82A4 w6 0xAB1C5ED5 w7 s3

        s5 =
            twoRounds 0xD807AA98 w8 0x12835B01 w9 s4

        s6 =
            twoRounds 0x243185BE w10 0x550C7DC3 w11 s5

        s7 =
            twoRounds 0x72BE5D74 w12 0x80DEB1FE w13 s6

        s8 =
            twoRounds 0x9BDC06A7 w14 0xC19BF174 w15 s7

        s9 =
            twoRounds 0xE49B69C1 w16 0xEFBE4786 w17 s8

        s10 =
            twoRounds 0x0FC19DC6 w18 0x240CA1CC w19 s9

        s11 =
            twoRounds 0x2DE92C6F w20 0x4A7484AA w21 s10

        s12 =
            twoRounds 0x5CB0A9DC w22 0x76F988DA w23 s11

        s13 =
            twoRounds 0x983E5152 w24 0xA831C66D w25 s12

        s14 =
            twoRounds 0xB00327C8 w26 0xBF597FC7 w27 s13

        s15 =
            twoRounds 0xC6E00BF3 w28 0xD5A79147 w29 s14

        s16 =
            twoRounds 0x06CA6351 w30 0x14292967 w31 s15

        s17 =
            twoRounds 0x27B70A85 w32 0x2E1B2138 w33 s16

        s18 =
            twoRounds 0x4D2C6DFC w34 0x53380D13 w35 s17

        s19 =
            twoRounds 0x650A7354 w36 0x766A0ABB w37 s18

        s20 =
            twoRounds 0x81C2C92E w38 0x92722C85 w39 s19

        s21 =
            twoRounds 0xA2BFE8A1 w40 0xA81A664B w41 s20

        s22 =
            twoRounds 0xC24B8B70 w42 0xC76C51A3 w43 s21

        s23 =
            twoRounds 0xD192E819 w44 0xD6990624 w45 s22

        s24 =
            twoRounds 0xF40E3585 w46 0x106AA070 w47 s23

        s25 =
            twoRounds 0x19A4C116 w48 0x1E376C08 w49 s24

        s26 =
            twoRounds 0x2748774C w50 0x34B0BCB5 w51 s25

        s27 =
            twoRounds 0x391C0CB3 w52 0x4ED8AA4A w53 s26

        s28 =
            twoRounds 0x5B9CCA4F w54 0x682E6FF3 w55 s27

        s29 =
            twoRounds 0x748F82EE w56 0x78A5636F w57 s28

        s30 =
            twoRounds 0x84C87814 w58 0x8CC70208 w59 s29

        s31 =
            twoRounds 0x90BEFFFA w60 0xA4506CEB w61 s30

        s32 =
            twoRounds 0xBEF9A3F7 w62 0xC67178F2 w63 s31
    in
    { h0 = state.h0 + s32.a |> unsigned
    , h1 = state.h1 + s32.b |> unsigned
    , h2 = state.h2 + s32.c |> unsigned
    , h3 = state.h3 + s32.d |> unsigned
    , h4 = state.h4 + s32.e |> unsigned
    , h5 = state.h5 + s32.f |> unsigned
    , h6 = state.h6 + s32.g |> unsigned
    , h7 = state.h7 + s32.h |> unsigned
    }



-- SHA-256 helper functions


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
