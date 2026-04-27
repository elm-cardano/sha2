module SHA512.V3 exposing (hash)

{-| [SHA-512] is a [cryptographic hash function] that gives 256 bits of security.

[SHA-512]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
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


{-| An abstract sha512 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int Int Int Int Int Int Int Int Int Int


{-| Compute SHA-512 hash of bytes.
-}
hash : Bytes -> Bytes
hash bytes =
    fromBytes bytes |> toBytes



-- Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).
-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        byteCount =
            Bytes.width bytes

        remainderMod128 =
            byteCount |> modBy 128

        paddingZeros =
            if remainderMod128 < 112 then
                111 - remainderMod128

            else
                239 - remainderMod128

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
                    , Encode.unsignedInt32 BE 0
                    , Encode.unsignedInt32 BE 0
                    , Encode.unsignedInt32 BE bitLenHi
                    , Encode.unsignedInt32 BE bitLenLo
                    ]
                )

        totalBlocks =
            Bytes.width paddedBytes // 128
    in
    case Decode.decode (blocksDecoder totalBlocks) paddedBytes of
        Just digest ->
            digest

        Nothing ->
            Digest 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0


blocksDecoder : Int -> Decoder Digest
blocksDecoder totalBlocks =
    Decode.loop
        { remaining = totalBlocks
        , h0h = 0x6A09E667
        , h0l = 0xF3BCC908
        , h1h = 0xBB67AE85
        , h1l = 0x84CAA73B
        , h2h = 0x3C6EF372
        , h2l = 0xFE94F82B
        , h3h = 0xA54FF53A
        , h3l = 0x5F1D36F1
        , h4h = 0x510E527F
        , h4l = 0xADE682D1
        , h5h = 0x9B05688C
        , h5l = 0x2B3E6C1F
        , h6h = 0x1F83D9AB
        , h6l = 0xFB41BD6B
        , h7h = 0x5BE0CD19
        , h7l = 0x137E2179
        }
        blockStep


type alias BlockState =
    { remaining : Int
    , h0h : Int
    , h0l : Int
    , h1h : Int
    , h1l : Int
    , h2h : Int
    , h2l : Int
    , h3h : Int
    , h3l : Int
    , h4h : Int
    , h4l : Int
    , h5h : Int
    , h5l : Int
    , h6h : Int
    , h6l : Int
    , h7h : Int
    , h7l : Int
    }


{-| 4 message words (64-bit each = 8 u32), decoded as a quarter-block.
-}
type alias QuarterBlock =
    { w0h : Int
    , w0l : Int
    , w1h : Int
    , w1l : Int
    , w2h : Int
    , w2l : Int
    , w3h : Int
    , w3l : Int
    }


blockStep : BlockState -> Decoder (Step BlockState Digest)
blockStep state =
    if state.remaining <= 0 then
        Decode.succeed
            (Done
                (Digest
                    state.h0h
                    state.h0l
                    state.h1h
                    state.h1l
                    state.h2h
                    state.h2l
                    state.h3h
                    state.h3l
                    state.h4h
                    state.h4l
                    state.h5h
                    state.h5l
                    state.h6h
                    state.h6l
                    state.h7h
                    state.h7l
                )
            )

    else
        Decode.map4
            (\q1 q2 q3 q4 ->
                let
                    result =
                        compress state q1 q2 q3 q4
                in
                Loop
                    { remaining = state.remaining - 1
                    , h0h = result.h0h
                    , h0l = result.h0l
                    , h1h = result.h1h
                    , h1l = result.h1l
                    , h2h = result.h2h
                    , h2l = result.h2l
                    , h3h = result.h3h
                    , h3l = result.h3l
                    , h4h = result.h4h
                    , h4l = result.h4l
                    , h5h = result.h5h
                    , h5l = result.h5l
                    , h6h = result.h6h
                    , h6l = result.h6l
                    , h7h = result.h7h
                    , h7l = result.h7l
                    }
            )
            quarterBlockDecoder
            quarterBlockDecoder
            quarterBlockDecoder
            quarterBlockDecoder


{-| Decode 4 big-endian u64 words (= 8 u32). Inner map5 decodes 5 u32 and returns
an F3 closure; outer map4 feeds the remaining 3 u32 via A3 fast-path. No tuples.
-}
quarterBlockDecoder : Decoder QuarterBlock
quarterBlockDecoder =
    Decode.map4 (\partial f g h -> partial f g h)
        (Decode.map5 (\a b c d e -> \f g h -> QuarterBlock a b c d e f g h) u32 u32 u32 u32 u32)
        u32
        u32
        u32


u32 : Decoder Int
u32 =
    Decode.unsignedInt32 BE


type alias RoundState =
    { aHi : Int
    , aLo : Int
    , bHi : Int
    , bLo : Int
    , cHi : Int
    , cLo : Int
    , dHi : Int
    , dLo : Int
    , eHi : Int
    , eLo : Int
    , fHi : Int
    , fLo : Int
    , gHi : Int
    , gLo : Int
    , hHi : Int
    , hLo : Int
    }


{-| Execute two SHA-512 compression rounds. F9 function (within Elm's fast-call path).
Takes two (k\_hi, k\_lo, w\_hi, w\_lo) quads and the current 8-word working state.
-}
twoRounds : Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> RoundState -> RoundState
twoRounds k0h k0l w0h w0l k1h k1l w1h w1l s =
    let
        -- Round A: t1 = h + bsig1(e) + ch(e,f,g) + k0 + w0
        bs1h =
            bsig1Hi s.eHi s.eLo

        bs1l =
            bsig1Lo s.eHi s.eLo

        chh =
            Bitwise.xor s.gHi (Bitwise.and s.eHi (Bitwise.xor s.fHi s.gHi))

        chl =
            Bitwise.xor s.gLo (Bitwise.and s.eLo (Bitwise.xor s.fLo s.gLo))

        t1als =
            unsigned s.hLo + unsigned bs1l + unsigned chl + unsigned k0l + unsigned w0l

        t1al =
            unsigned t1als

        t1ah =
            s.hHi + bs1h + chh + k0h + w0h + t1als // 4294967296 |> unsigned

        -- Round A: t2 = bsig0(a) + maj(a,b,c)
        bs0h =
            bsig0Hi s.aHi s.aLo

        bs0l =
            bsig0Lo s.aHi s.aLo

        mjh =
            Bitwise.xor (Bitwise.xor (Bitwise.and s.aHi s.bHi) (Bitwise.and s.aHi s.cHi)) (Bitwise.and s.bHi s.cHi)

        mjl =
            Bitwise.xor (Bitwise.xor (Bitwise.and s.aLo s.bLo) (Bitwise.and s.aLo s.cLo)) (Bitwise.and s.bLo s.cLo)

        t2als =
            unsigned bs0l + unsigned mjl

        t2al =
            unsigned t2als

        t2ah =
            bs0h + mjh + t2als // 4294967296 |> unsigned

        -- newA = t1 + t2
        a1ls =
            unsigned t1al + unsigned t2al

        a1l =
            unsigned a1ls

        a1h =
            t1ah + t2ah + a1ls // 4294967296 |> unsigned

        -- newE = d + t1
        e1ls =
            unsigned s.dLo + unsigned t1al

        e1l =
            unsigned e1ls

        e1h =
            s.dHi + t1ah + e1ls // 4294967296 |> unsigned

        -- Round B: state is (a1, s.a, s.b, s.c, e1, s.e, s.f, s.g)
        bs1h2 =
            bsig1Hi e1h e1l

        bs1l2 =
            bsig1Lo e1h e1l

        chh2 =
            Bitwise.xor s.fHi (Bitwise.and e1h (Bitwise.xor s.eHi s.fHi))

        chl2 =
            Bitwise.xor s.fLo (Bitwise.and e1l (Bitwise.xor s.eLo s.fLo))

        t1bls =
            unsigned s.gLo + unsigned bs1l2 + unsigned chl2 + unsigned k1l + unsigned w1l

        t1bl =
            unsigned t1bls

        t1bh =
            s.gHi + bs1h2 + chh2 + k1h + w1h + t1bls // 4294967296 |> unsigned

        bs0h2 =
            bsig0Hi a1h a1l

        bs0l2 =
            bsig0Lo a1h a1l

        mjh2 =
            Bitwise.xor (Bitwise.xor (Bitwise.and a1h s.aHi) (Bitwise.and a1h s.bHi)) (Bitwise.and s.aHi s.bHi)

        mjl2 =
            Bitwise.xor (Bitwise.xor (Bitwise.and a1l s.aLo) (Bitwise.and a1l s.bLo)) (Bitwise.and s.aLo s.bLo)

        t2bls =
            unsigned bs0l2 + unsigned mjl2

        t2bl =
            unsigned t2bls

        t2bh =
            bs0h2 + mjh2 + t2bls // 4294967296 |> unsigned

        a2ls =
            unsigned t1bl + unsigned t2bl

        a2l =
            unsigned a2ls

        a2h =
            t1bh + t2bh + a2ls // 4294967296 |> unsigned

        e2ls =
            unsigned s.cLo + unsigned t1bl

        e2l =
            unsigned e2ls

        e2h =
            s.cHi + t1bh + e2ls // 4294967296 |> unsigned
    in
    { aHi = a2h, aLo = a2l, bHi = a1h, bLo = a1l, cHi = s.aHi, cLo = s.aLo, dHi = s.bHi, dLo = s.bLo, eHi = e2h, eLo = e2l, fHi = e1h, fLo = e1l, gHi = s.eHi, gLo = s.eLo, hHi = s.fHi, hLo = s.fLo }


{-| Compute one message schedule word: ssig1(a) + b + ssig0(c) + d (all 64-bit).
F8 function within Elm's fast-call path.
-}
scheduleWord : Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> { hi : Int, lo : Int }
scheduleWord a2h a2l b7h b7l c15h c15l d16h d16l =
    let
        s1l =
            ssig1Lo a2h a2l

        s0l =
            ssig0Lo c15h c15l

        loSum =
            unsigned s1l + unsigned b7l + unsigned s0l + unsigned d16l
    in
    { hi = ssig1Hi a2h a2l + b7h + ssig0Hi c15h c15l + d16h + loSum // 4294967296 |> unsigned
    , lo = unsigned loSum
    }


{-| SHA-512 compression function. Takes the current hash state and 16 message words
(as four QuarterBlocks), expands the message schedule and runs all 80 rounds via twoRounds.
-}
compress : BlockState -> QuarterBlock -> QuarterBlock -> QuarterBlock -> QuarterBlock -> { h0h : Int, h0l : Int, h1h : Int, h1l : Int, h2h : Int, h2l : Int, h3h : Int, h3l : Int, h4h : Int, h4l : Int, h5h : Int, h5l : Int, h6h : Int, h6l : Int, h7h : Int, h7l : Int }
compress state q1 q2 q3 q4 =
    let
        -- Extract 16 64-bit message words (each as hi/lo pair)
        w0h =
            q1.w0h

        w0l =
            q1.w0l

        w1h =
            q1.w1h

        w1l =
            q1.w1l

        w2h =
            q1.w2h

        w2l =
            q1.w2l

        w3h =
            q1.w3h

        w3l =
            q1.w3l

        w4h =
            q2.w0h

        w4l =
            q2.w0l

        w5h =
            q2.w1h

        w5l =
            q2.w1l

        w6h =
            q2.w2h

        w6l =
            q2.w2l

        w7h =
            q2.w3h

        w7l =
            q2.w3l

        w8h =
            q3.w0h

        w8l =
            q3.w0l

        w9h =
            q3.w1h

        w9l =
            q3.w1l

        w10h =
            q3.w2h

        w10l =
            q3.w2l

        w11h =
            q3.w3h

        w11l =
            q3.w3l

        w12h =
            q4.w0h

        w12l =
            q4.w0l

        w13h =
            q4.w1h

        w13l =
            q4.w1l

        w14h =
            q4.w2h

        w14l =
            q4.w2l

        w15h =
            q4.w3h

        w15l =
            q4.w3l

        -- Message schedule expansion w16..w79
        sw16 =
            scheduleWord w14h w14l w9h w9l w1h w1l w0h w0l

        sw17 =
            scheduleWord w15h w15l w10h w10l w2h w2l w1h w1l

        sw18 =
            scheduleWord sw16.hi sw16.lo w11h w11l w3h w3l w2h w2l

        sw19 =
            scheduleWord sw17.hi sw17.lo w12h w12l w4h w4l w3h w3l

        sw20 =
            scheduleWord sw18.hi sw18.lo w13h w13l w5h w5l w4h w4l

        sw21 =
            scheduleWord sw19.hi sw19.lo w14h w14l w6h w6l w5h w5l

        sw22 =
            scheduleWord sw20.hi sw20.lo w15h w15l w7h w7l w6h w6l

        sw23 =
            scheduleWord sw21.hi sw21.lo sw16.hi sw16.lo w8h w8l w7h w7l

        sw24 =
            scheduleWord sw22.hi sw22.lo sw17.hi sw17.lo w9h w9l w8h w8l

        sw25 =
            scheduleWord sw23.hi sw23.lo sw18.hi sw18.lo w10h w10l w9h w9l

        sw26 =
            scheduleWord sw24.hi sw24.lo sw19.hi sw19.lo w11h w11l w10h w10l

        sw27 =
            scheduleWord sw25.hi sw25.lo sw20.hi sw20.lo w12h w12l w11h w11l

        sw28 =
            scheduleWord sw26.hi sw26.lo sw21.hi sw21.lo w13h w13l w12h w12l

        sw29 =
            scheduleWord sw27.hi sw27.lo sw22.hi sw22.lo w14h w14l w13h w13l

        sw30 =
            scheduleWord sw28.hi sw28.lo sw23.hi sw23.lo w15h w15l w14h w14l

        sw31 =
            scheduleWord sw29.hi sw29.lo sw24.hi sw24.lo sw16.hi sw16.lo w15h w15l

        sw32 =
            scheduleWord sw30.hi sw30.lo sw25.hi sw25.lo sw17.hi sw17.lo sw16.hi sw16.lo

        sw33 =
            scheduleWord sw31.hi sw31.lo sw26.hi sw26.lo sw18.hi sw18.lo sw17.hi sw17.lo

        sw34 =
            scheduleWord sw32.hi sw32.lo sw27.hi sw27.lo sw19.hi sw19.lo sw18.hi sw18.lo

        sw35 =
            scheduleWord sw33.hi sw33.lo sw28.hi sw28.lo sw20.hi sw20.lo sw19.hi sw19.lo

        sw36 =
            scheduleWord sw34.hi sw34.lo sw29.hi sw29.lo sw21.hi sw21.lo sw20.hi sw20.lo

        sw37 =
            scheduleWord sw35.hi sw35.lo sw30.hi sw30.lo sw22.hi sw22.lo sw21.hi sw21.lo

        sw38 =
            scheduleWord sw36.hi sw36.lo sw31.hi sw31.lo sw23.hi sw23.lo sw22.hi sw22.lo

        sw39 =
            scheduleWord sw37.hi sw37.lo sw32.hi sw32.lo sw24.hi sw24.lo sw23.hi sw23.lo

        sw40 =
            scheduleWord sw38.hi sw38.lo sw33.hi sw33.lo sw25.hi sw25.lo sw24.hi sw24.lo

        sw41 =
            scheduleWord sw39.hi sw39.lo sw34.hi sw34.lo sw26.hi sw26.lo sw25.hi sw25.lo

        sw42 =
            scheduleWord sw40.hi sw40.lo sw35.hi sw35.lo sw27.hi sw27.lo sw26.hi sw26.lo

        sw43 =
            scheduleWord sw41.hi sw41.lo sw36.hi sw36.lo sw28.hi sw28.lo sw27.hi sw27.lo

        sw44 =
            scheduleWord sw42.hi sw42.lo sw37.hi sw37.lo sw29.hi sw29.lo sw28.hi sw28.lo

        sw45 =
            scheduleWord sw43.hi sw43.lo sw38.hi sw38.lo sw30.hi sw30.lo sw29.hi sw29.lo

        sw46 =
            scheduleWord sw44.hi sw44.lo sw39.hi sw39.lo sw31.hi sw31.lo sw30.hi sw30.lo

        sw47 =
            scheduleWord sw45.hi sw45.lo sw40.hi sw40.lo sw32.hi sw32.lo sw31.hi sw31.lo

        sw48 =
            scheduleWord sw46.hi sw46.lo sw41.hi sw41.lo sw33.hi sw33.lo sw32.hi sw32.lo

        sw49 =
            scheduleWord sw47.hi sw47.lo sw42.hi sw42.lo sw34.hi sw34.lo sw33.hi sw33.lo

        sw50 =
            scheduleWord sw48.hi sw48.lo sw43.hi sw43.lo sw35.hi sw35.lo sw34.hi sw34.lo

        sw51 =
            scheduleWord sw49.hi sw49.lo sw44.hi sw44.lo sw36.hi sw36.lo sw35.hi sw35.lo

        sw52 =
            scheduleWord sw50.hi sw50.lo sw45.hi sw45.lo sw37.hi sw37.lo sw36.hi sw36.lo

        sw53 =
            scheduleWord sw51.hi sw51.lo sw46.hi sw46.lo sw38.hi sw38.lo sw37.hi sw37.lo

        sw54 =
            scheduleWord sw52.hi sw52.lo sw47.hi sw47.lo sw39.hi sw39.lo sw38.hi sw38.lo

        sw55 =
            scheduleWord sw53.hi sw53.lo sw48.hi sw48.lo sw40.hi sw40.lo sw39.hi sw39.lo

        sw56 =
            scheduleWord sw54.hi sw54.lo sw49.hi sw49.lo sw41.hi sw41.lo sw40.hi sw40.lo

        sw57 =
            scheduleWord sw55.hi sw55.lo sw50.hi sw50.lo sw42.hi sw42.lo sw41.hi sw41.lo

        sw58 =
            scheduleWord sw56.hi sw56.lo sw51.hi sw51.lo sw43.hi sw43.lo sw42.hi sw42.lo

        sw59 =
            scheduleWord sw57.hi sw57.lo sw52.hi sw52.lo sw44.hi sw44.lo sw43.hi sw43.lo

        sw60 =
            scheduleWord sw58.hi sw58.lo sw53.hi sw53.lo sw45.hi sw45.lo sw44.hi sw44.lo

        sw61 =
            scheduleWord sw59.hi sw59.lo sw54.hi sw54.lo sw46.hi sw46.lo sw45.hi sw45.lo

        sw62 =
            scheduleWord sw60.hi sw60.lo sw55.hi sw55.lo sw47.hi sw47.lo sw46.hi sw46.lo

        sw63 =
            scheduleWord sw61.hi sw61.lo sw56.hi sw56.lo sw48.hi sw48.lo sw47.hi sw47.lo

        sw64 =
            scheduleWord sw62.hi sw62.lo sw57.hi sw57.lo sw49.hi sw49.lo sw48.hi sw48.lo

        sw65 =
            scheduleWord sw63.hi sw63.lo sw58.hi sw58.lo sw50.hi sw50.lo sw49.hi sw49.lo

        sw66 =
            scheduleWord sw64.hi sw64.lo sw59.hi sw59.lo sw51.hi sw51.lo sw50.hi sw50.lo

        sw67 =
            scheduleWord sw65.hi sw65.lo sw60.hi sw60.lo sw52.hi sw52.lo sw51.hi sw51.lo

        sw68 =
            scheduleWord sw66.hi sw66.lo sw61.hi sw61.lo sw53.hi sw53.lo sw52.hi sw52.lo

        sw69 =
            scheduleWord sw67.hi sw67.lo sw62.hi sw62.lo sw54.hi sw54.lo sw53.hi sw53.lo

        sw70 =
            scheduleWord sw68.hi sw68.lo sw63.hi sw63.lo sw55.hi sw55.lo sw54.hi sw54.lo

        sw71 =
            scheduleWord sw69.hi sw69.lo sw64.hi sw64.lo sw56.hi sw56.lo sw55.hi sw55.lo

        sw72 =
            scheduleWord sw70.hi sw70.lo sw65.hi sw65.lo sw57.hi sw57.lo sw56.hi sw56.lo

        sw73 =
            scheduleWord sw71.hi sw71.lo sw66.hi sw66.lo sw58.hi sw58.lo sw57.hi sw57.lo

        sw74 =
            scheduleWord sw72.hi sw72.lo sw67.hi sw67.lo sw59.hi sw59.lo sw58.hi sw58.lo

        sw75 =
            scheduleWord sw73.hi sw73.lo sw68.hi sw68.lo sw60.hi sw60.lo sw59.hi sw59.lo

        sw76 =
            scheduleWord sw74.hi sw74.lo sw69.hi sw69.lo sw61.hi sw61.lo sw60.hi sw60.lo

        sw77 =
            scheduleWord sw75.hi sw75.lo sw70.hi sw70.lo sw62.hi sw62.lo sw61.hi sw61.lo

        sw78 =
            scheduleWord sw76.hi sw76.lo sw71.hi sw71.lo sw63.hi sw63.lo sw62.hi sw62.lo

        sw79 =
            scheduleWord sw77.hi sw77.lo sw72.hi sw72.lo sw64.hi sw64.lo sw63.hi sw63.lo

        -- Initial round state
        s0 =
            { aHi = state.h0h, aLo = state.h0l, bHi = state.h1h, bLo = state.h1l, cHi = state.h2h, cLo = state.h2l, dHi = state.h3h, dLo = state.h3l, eHi = state.h4h, eLo = state.h4l, fHi = state.h5h, fLo = state.h5l, gHi = state.h6h, gLo = state.h6l, hHi = state.h7h, hLo = state.h7l }

        -- 40 calls to twoRounds (80 rounds total)
        s1 =
            twoRounds 0x428A2F98 0xD728AE22 w0h w0l 0x71374491 0x23EF65CD w1h w1l s0

        s2 =
            twoRounds 0xB5C0FBCF 0xEC4D3B2F w2h w2l 0xE9B5DBA5 0x8189DBBC w3h w3l s1

        s3 =
            twoRounds 0x3956C25B 0xF348B538 w4h w4l 0x59F111F1 0xB605D019 w5h w5l s2

        s4 =
            twoRounds 0x923F82A4 0xAF194F9B w6h w6l 0xAB1C5ED5 0xDA6D8118 w7h w7l s3

        s5 =
            twoRounds 0xD807AA98 0xA3030242 w8h w8l 0x12835B01 0x45706FBE w9h w9l s4

        s6 =
            twoRounds 0x243185BE 0x4EE4B28C w10h w10l 0x550C7DC3 0xD5FFB4E2 w11h w11l s5

        s7 =
            twoRounds 0x72BE5D74 0xF27B896F w12h w12l 0x80DEB1FE 0x3B1696B1 w13h w13l s6

        s8 =
            twoRounds 0x9BDC06A7 0x25C71235 w14h w14l 0xC19BF174 0xCF692694 w15h w15l s7

        s9 =
            twoRounds 0xE49B69C1 0x9EF14AD2 sw16.hi sw16.lo 0xEFBE4786 0x384F25E3 sw17.hi sw17.lo s8

        s10 =
            twoRounds 0x0FC19DC6 0x8B8CD5B5 sw18.hi sw18.lo 0x240CA1CC 0x77AC9C65 sw19.hi sw19.lo s9

        s11 =
            twoRounds 0x2DE92C6F 0x592B0275 sw20.hi sw20.lo 0x4A7484AA 0x6EA6E483 sw21.hi sw21.lo s10

        s12 =
            twoRounds 0x5CB0A9DC 0xBD41FBD4 sw22.hi sw22.lo 0x76F988DA 0x831153B5 sw23.hi sw23.lo s11

        s13 =
            twoRounds 0x983E5152 0xEE66DFAB sw24.hi sw24.lo 0xA831C66D 0x2DB43210 sw25.hi sw25.lo s12

        s14 =
            twoRounds 0xB00327C8 0x98FB213F sw26.hi sw26.lo 0xBF597FC7 0xBEEF0EE4 sw27.hi sw27.lo s13

        s15 =
            twoRounds 0xC6E00BF3 0x3DA88FC2 sw28.hi sw28.lo 0xD5A79147 0x930AA725 sw29.hi sw29.lo s14

        s16 =
            twoRounds 0x06CA6351 0xE003826F sw30.hi sw30.lo 0x14292967 0x0A0E6E70 sw31.hi sw31.lo s15

        s17 =
            twoRounds 0x27B70A85 0x46D22FFC sw32.hi sw32.lo 0x2E1B2138 0x5C26C926 sw33.hi sw33.lo s16

        s18 =
            twoRounds 0x4D2C6DFC 0x5AC42AED sw34.hi sw34.lo 0x53380D13 0x9D95B3DF sw35.hi sw35.lo s17

        s19 =
            twoRounds 0x650A7354 0x8BAF63DE sw36.hi sw36.lo 0x766A0ABB 0x3C77B2A8 sw37.hi sw37.lo s18

        s20 =
            twoRounds 0x81C2C92E 0x47EDAEE6 sw38.hi sw38.lo 0x92722C85 0x1482353B sw39.hi sw39.lo s19

        s21 =
            twoRounds 0xA2BFE8A1 0x4CF10364 sw40.hi sw40.lo 0xA81A664B 0xBC423001 sw41.hi sw41.lo s20

        s22 =
            twoRounds 0xC24B8B70 0xD0F89791 sw42.hi sw42.lo 0xC76C51A3 0x0654BE30 sw43.hi sw43.lo s21

        s23 =
            twoRounds 0xD192E819 0xD6EF5218 sw44.hi sw44.lo 0xD6990624 0x5565A910 sw45.hi sw45.lo s22

        s24 =
            twoRounds 0xF40E3585 0x5771202A sw46.hi sw46.lo 0x106AA070 0x32BBD1B8 sw47.hi sw47.lo s23

        s25 =
            twoRounds 0x19A4C116 0xB8D2D0C8 sw48.hi sw48.lo 0x1E376C08 0x5141AB53 sw49.hi sw49.lo s24

        s26 =
            twoRounds 0x2748774C 0xDF8EEB99 sw50.hi sw50.lo 0x34B0BCB5 0xE19B48A8 sw51.hi sw51.lo s25

        s27 =
            twoRounds 0x391C0CB3 0xC5C95A63 sw52.hi sw52.lo 0x4ED8AA4A 0xE3418ACB sw53.hi sw53.lo s26

        s28 =
            twoRounds 0x5B9CCA4F 0x7763E373 sw54.hi sw54.lo 0x682E6FF3 0xD6B2B8A3 sw55.hi sw55.lo s27

        s29 =
            twoRounds 0x748F82EE 0x5DEFB2FC sw56.hi sw56.lo 0x78A5636F 0x43172F60 sw57.hi sw57.lo s28

        s30 =
            twoRounds 0x84C87814 0xA1F0AB72 sw58.hi sw58.lo 0x8CC70208 0x1A6439EC sw59.hi sw59.lo s29

        s31 =
            twoRounds 0x90BEFFFA 0x23631E28 sw60.hi sw60.lo 0xA4506CEB 0xDE82BDE9 sw61.hi sw61.lo s30

        s32 =
            twoRounds 0xBEF9A3F7 0xB2C67915 sw62.hi sw62.lo 0xC67178F2 0xE372532B sw63.hi sw63.lo s31

        s33 =
            twoRounds 0xCA273ECE 0xEA26619C sw64.hi sw64.lo 0xD186B8C7 0x21C0C207 sw65.hi sw65.lo s32

        s34 =
            twoRounds 0xEADA7DD6 0xCDE0EB1E sw66.hi sw66.lo 0xF57D4F7F 0xEE6ED178 sw67.hi sw67.lo s33

        s35 =
            twoRounds 0x06F067AA 0x72176FBA sw68.hi sw68.lo 0x0A637DC5 0xA2C898A6 sw69.hi sw69.lo s34

        s36 =
            twoRounds 0x113F9804 0xBEF90DAE sw70.hi sw70.lo 0x1B710B35 0x131C471B sw71.hi sw71.lo s35

        s37 =
            twoRounds 0x28DB77F5 0x23047D84 sw72.hi sw72.lo 0x32CAAB7B 0x40C72493 sw73.hi sw73.lo s36

        s38 =
            twoRounds 0x3C9EBE0A 0x15C9BEBC sw74.hi sw74.lo 0x431D67C4 0x9C100D4C sw75.hi sw75.lo s37

        s39 =
            twoRounds 0x4CC5D4BE 0xCB3E42B6 sw76.hi sw76.lo 0x597F299C 0xFC657E2A sw77.hi sw77.lo s38

        s40 =
            twoRounds 0x5FCB6FAB 0x3AD6FAEC sw78.hi sw78.lo 0x6C44198C 0x4A475817 sw79.hi sw79.lo s39

        -- Final hash additions (64-bit add with carry)
        ls0 =
            unsigned state.h0l + unsigned s40.aLo

        ls1 =
            unsigned state.h1l + unsigned s40.bLo

        ls2 =
            unsigned state.h2l + unsigned s40.cLo

        ls3 =
            unsigned state.h3l + unsigned s40.dLo

        ls4 =
            unsigned state.h4l + unsigned s40.eLo

        ls5 =
            unsigned state.h5l + unsigned s40.fLo

        ls6 =
            unsigned state.h6l + unsigned s40.gLo

        ls7 =
            unsigned state.h7l + unsigned s40.hLo
    in
    { h0h = state.h0h + s40.aHi + ls0 // 4294967296 |> unsigned
    , h0l = unsigned ls0
    , h1h = state.h1h + s40.bHi + ls1 // 4294967296 |> unsigned
    , h1l = unsigned ls1
    , h2h = state.h2h + s40.cHi + ls2 // 4294967296 |> unsigned
    , h2l = unsigned ls2
    , h3h = state.h3h + s40.dHi + ls3 // 4294967296 |> unsigned
    , h3l = unsigned ls3
    , h4h = state.h4h + s40.eHi + ls4 // 4294967296 |> unsigned
    , h4l = unsigned ls4
    , h5h = state.h5h + s40.fHi + ls5 // 4294967296 |> unsigned
    , h5l = unsigned ls5
    , h6h = state.h6h + s40.gHi + ls6 // 4294967296 |> unsigned
    , h6l = unsigned ls6
    , h7h = state.h7h + s40.hHi + ls7 // 4294967296 |> unsigned
    , h7l = unsigned ls7
    }



-- SHA-512 sigma helper functions (each is F2, within fast-call path)


bsig0Hi : Int -> Int -> Int
bsig0Hi xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 28 xh) (Bitwise.shiftLeftBy 4 xl))
            (Bitwise.or (Bitwise.shiftRightZfBy 2 xl) (Bitwise.shiftLeftBy 30 xh))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 7 xl) (Bitwise.shiftLeftBy 25 xh))


bsig0Lo : Int -> Int -> Int
bsig0Lo xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 28 xl) (Bitwise.shiftLeftBy 4 xh))
            (Bitwise.or (Bitwise.shiftRightZfBy 2 xh) (Bitwise.shiftLeftBy 30 xl))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 7 xh) (Bitwise.shiftLeftBy 25 xl))


bsig1Hi : Int -> Int -> Int
bsig1Hi xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 14 xh) (Bitwise.shiftLeftBy 18 xl))
            (Bitwise.or (Bitwise.shiftRightZfBy 18 xh) (Bitwise.shiftLeftBy 14 xl))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 9 xl) (Bitwise.shiftLeftBy 23 xh))


bsig1Lo : Int -> Int -> Int
bsig1Lo xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 14 xl) (Bitwise.shiftLeftBy 18 xh))
            (Bitwise.or (Bitwise.shiftRightZfBy 18 xl) (Bitwise.shiftLeftBy 14 xh))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 9 xh) (Bitwise.shiftLeftBy 23 xl))


ssig0Hi : Int -> Int -> Int
ssig0Hi xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 1 xh) (Bitwise.shiftLeftBy 31 xl))
            (Bitwise.or (Bitwise.shiftRightZfBy 8 xh) (Bitwise.shiftLeftBy 24 xl))
        )
        (Bitwise.shiftRightZfBy 7 xh)


ssig0Lo : Int -> Int -> Int
ssig0Lo xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 1 xl) (Bitwise.shiftLeftBy 31 xh))
            (Bitwise.or (Bitwise.shiftRightZfBy 8 xl) (Bitwise.shiftLeftBy 24 xh))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 7 xl) (Bitwise.shiftLeftBy 25 xh))


ssig1Hi : Int -> Int -> Int
ssig1Hi xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 19 xh) (Bitwise.shiftLeftBy 13 xl))
            (Bitwise.or (Bitwise.shiftRightZfBy 29 xl) (Bitwise.shiftLeftBy 3 xh))
        )
        (Bitwise.shiftRightZfBy 6 xh)


ssig1Lo : Int -> Int -> Int
ssig1Lo xh xl =
    Bitwise.xor
        (Bitwise.xor
            (Bitwise.or (Bitwise.shiftRightZfBy 19 xl) (Bitwise.shiftLeftBy 13 xh))
            (Bitwise.or (Bitwise.shiftRightZfBy 29 xh) (Bitwise.shiftLeftBy 3 xl))
        )
        (Bitwise.or (Bitwise.shiftRightZfBy 6 xl) (Bitwise.shiftLeftBy 26 xh))


unsigned : Int -> Int
unsigned x =
    Bitwise.shiftRightZfBy 0 x


{-| Turn a digest into `Bytes`. The digest is stored as 8 big-endian 64-bit unsigned
integers (each as two 32-bit words), so the width is 64 bytes or 512 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l h6h h6l h7h h7l) =
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE h0h
            , Encode.unsignedInt32 BE h0l
            , Encode.unsignedInt32 BE h1h
            , Encode.unsignedInt32 BE h1l
            , Encode.unsignedInt32 BE h2h
            , Encode.unsignedInt32 BE h2l
            , Encode.unsignedInt32 BE h3h
            , Encode.unsignedInt32 BE h3l
            , Encode.unsignedInt32 BE h4h
            , Encode.unsignedInt32 BE h4l
            , Encode.unsignedInt32 BE h5h
            , Encode.unsignedInt32 BE h5l
            , Encode.unsignedInt32 BE h6h
            , Encode.unsignedInt32 BE h6l
            , Encode.unsignedInt32 BE h7h
            , Encode.unsignedInt32 BE h7l
            ]
        )
