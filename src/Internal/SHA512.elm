module Internal.SHA512 exposing (HashResult, hash)

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode


type alias HashResult =
    { h0h : Int
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


hash : HashResult -> Bytes -> HashResult
hash initialState bytes =
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
    case Decode.decode (blocksDecoder totalBlocks initialState) paddedBytes of
        Just result ->
            result

        Nothing ->
            { h0h = 0, h0l = 0, h1h = 0, h1l = 0, h2h = 0, h2l = 0, h3h = 0, h3l = 0, h4h = 0, h4l = 0, h5h = 0, h5l = 0, h6h = 0, h6l = 0, h7h = 0, h7l = 0 }


blocksDecoder : Int -> HashResult -> Decoder HashResult
blocksDecoder totalBlocks initial =
    Decode.loop
        { remaining = totalBlocks
        , h0h = initial.h0h
        , h0l = initial.h0l
        , h1h = initial.h1h
        , h1l = initial.h1l
        , h2h = initial.h2h
        , h2l = initial.h2l
        , h3h = initial.h3h
        , h3l = initial.h3l
        , h4h = initial.h4h
        , h4l = initial.h4l
        , h5h = initial.h5h
        , h5l = initial.h5l
        , h6h = initial.h6h
        , h6l = initial.h6l
        , h7h = initial.h7h
        , h7l = initial.h7l
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


blockStep : BlockState -> Decoder (Step BlockState HashResult)
blockStep state =
    if state.remaining <= 0 then
        Decode.succeed
            (Done
                { h0h = state.h0h
                , h0l = state.h0l
                , h1h = state.h1h
                , h1l = state.h1l
                , h2h = state.h2h
                , h2l = state.h2l
                , h3h = state.h3h
                , h3l = state.h3l
                , h4h = state.h4h
                , h4l = state.h4l
                , h5h = state.h5h
                , h5l = state.h5l
                , h6h = state.h6h
                , h6l = state.h6l
                , h7h = state.h7h
                , h7l = state.h7l
                }
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


type alias W64 =
    { hi : Int, lo : Int }


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


twoRounds : Int -> Int -> W64 -> Int -> Int -> W64 -> RoundState -> RoundState
twoRounds k0h k0l w0 k1h k1l w1 s =
    let
        bs1h =
            bsig1Hi s.eHi s.eLo

        bs1l =
            bsig1Lo s.eHi s.eLo

        chh =
            Bitwise.xor s.gHi (Bitwise.and s.eHi (Bitwise.xor s.fHi s.gHi))

        chl =
            Bitwise.xor s.gLo (Bitwise.and s.eLo (Bitwise.xor s.fLo s.gLo))

        t1als =
            unsigned s.hLo + unsigned bs1l + unsigned chl + unsigned k0l + unsigned w0.lo

        t1al =
            unsigned t1als

        t1ah =
            s.hHi + bs1h + chh + k0h + w0.hi + t1als // 4294967296 |> unsigned

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

        a1ls =
            unsigned t1al + unsigned t2al

        a1l =
            unsigned a1ls

        a1h =
            t1ah + t2ah + a1ls // 4294967296 |> unsigned

        e1ls =
            unsigned s.dLo + unsigned t1al

        e1l =
            unsigned e1ls

        e1h =
            s.dHi + t1ah + e1ls // 4294967296 |> unsigned

        bs1h2 =
            bsig1Hi e1h e1l

        bs1l2 =
            bsig1Lo e1h e1l

        chh2 =
            Bitwise.xor s.fHi (Bitwise.and e1h (Bitwise.xor s.eHi s.fHi))

        chl2 =
            Bitwise.xor s.fLo (Bitwise.and e1l (Bitwise.xor s.eLo s.fLo))

        t1bls =
            unsigned s.gLo + unsigned bs1l2 + unsigned chl2 + unsigned k1l + unsigned w1.lo

        t1bl =
            unsigned t1bls

        t1bh =
            s.gHi + bs1h2 + chh2 + k1h + w1.hi + t1bls // 4294967296 |> unsigned

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


scheduleWord : W64 -> W64 -> W64 -> W64 -> W64
scheduleWord a b c d =
    let
        loSum =
            unsigned (ssig1Lo a.hi a.lo) + unsigned b.lo + unsigned (ssig0Lo c.hi c.lo) + unsigned d.lo
    in
    { hi = ssig1Hi a.hi a.lo + b.hi + ssig0Hi c.hi c.lo + d.hi + loSum // 4294967296 |> unsigned
    , lo = unsigned loSum
    }


compress : BlockState -> QuarterBlock -> QuarterBlock -> QuarterBlock -> QuarterBlock -> HashResult
compress state q1 q2 q3 q4 =
    let
        w0 =
            { hi = q1.w0h, lo = q1.w0l }

        w1 =
            { hi = q1.w1h, lo = q1.w1l }

        w2 =
            { hi = q1.w2h, lo = q1.w2l }

        w3 =
            { hi = q1.w3h, lo = q1.w3l }

        w4 =
            { hi = q2.w0h, lo = q2.w0l }

        w5 =
            { hi = q2.w1h, lo = q2.w1l }

        w6 =
            { hi = q2.w2h, lo = q2.w2l }

        w7 =
            { hi = q2.w3h, lo = q2.w3l }

        w8 =
            { hi = q3.w0h, lo = q3.w0l }

        w9 =
            { hi = q3.w1h, lo = q3.w1l }

        w10 =
            { hi = q3.w2h, lo = q3.w2l }

        w11 =
            { hi = q3.w3h, lo = q3.w3l }

        w12 =
            { hi = q4.w0h, lo = q4.w0l }

        w13 =
            { hi = q4.w1h, lo = q4.w1l }

        w14 =
            { hi = q4.w2h, lo = q4.w2l }

        w15 =
            { hi = q4.w3h, lo = q4.w3l }

        sw16 =
            scheduleWord w14 w9 w1 w0

        sw17 =
            scheduleWord w15 w10 w2 w1

        sw18 =
            scheduleWord sw16 w11 w3 w2

        sw19 =
            scheduleWord sw17 w12 w4 w3

        sw20 =
            scheduleWord sw18 w13 w5 w4

        sw21 =
            scheduleWord sw19 w14 w6 w5

        sw22 =
            scheduleWord sw20 w15 w7 w6

        sw23 =
            scheduleWord sw21 sw16 w8 w7

        sw24 =
            scheduleWord sw22 sw17 w9 w8

        sw25 =
            scheduleWord sw23 sw18 w10 w9

        sw26 =
            scheduleWord sw24 sw19 w11 w10

        sw27 =
            scheduleWord sw25 sw20 w12 w11

        sw28 =
            scheduleWord sw26 sw21 w13 w12

        sw29 =
            scheduleWord sw27 sw22 w14 w13

        sw30 =
            scheduleWord sw28 sw23 w15 w14

        sw31 =
            scheduleWord sw29 sw24 sw16 w15

        sw32 =
            scheduleWord sw30 sw25 sw17 sw16

        sw33 =
            scheduleWord sw31 sw26 sw18 sw17

        sw34 =
            scheduleWord sw32 sw27 sw19 sw18

        sw35 =
            scheduleWord sw33 sw28 sw20 sw19

        sw36 =
            scheduleWord sw34 sw29 sw21 sw20

        sw37 =
            scheduleWord sw35 sw30 sw22 sw21

        sw38 =
            scheduleWord sw36 sw31 sw23 sw22

        sw39 =
            scheduleWord sw37 sw32 sw24 sw23

        sw40 =
            scheduleWord sw38 sw33 sw25 sw24

        sw41 =
            scheduleWord sw39 sw34 sw26 sw25

        sw42 =
            scheduleWord sw40 sw35 sw27 sw26

        sw43 =
            scheduleWord sw41 sw36 sw28 sw27

        sw44 =
            scheduleWord sw42 sw37 sw29 sw28

        sw45 =
            scheduleWord sw43 sw38 sw30 sw29

        sw46 =
            scheduleWord sw44 sw39 sw31 sw30

        sw47 =
            scheduleWord sw45 sw40 sw32 sw31

        sw48 =
            scheduleWord sw46 sw41 sw33 sw32

        sw49 =
            scheduleWord sw47 sw42 sw34 sw33

        sw50 =
            scheduleWord sw48 sw43 sw35 sw34

        sw51 =
            scheduleWord sw49 sw44 sw36 sw35

        sw52 =
            scheduleWord sw50 sw45 sw37 sw36

        sw53 =
            scheduleWord sw51 sw46 sw38 sw37

        sw54 =
            scheduleWord sw52 sw47 sw39 sw38

        sw55 =
            scheduleWord sw53 sw48 sw40 sw39

        sw56 =
            scheduleWord sw54 sw49 sw41 sw40

        sw57 =
            scheduleWord sw55 sw50 sw42 sw41

        sw58 =
            scheduleWord sw56 sw51 sw43 sw42

        sw59 =
            scheduleWord sw57 sw52 sw44 sw43

        sw60 =
            scheduleWord sw58 sw53 sw45 sw44

        sw61 =
            scheduleWord sw59 sw54 sw46 sw45

        sw62 =
            scheduleWord sw60 sw55 sw47 sw46

        sw63 =
            scheduleWord sw61 sw56 sw48 sw47

        sw64 =
            scheduleWord sw62 sw57 sw49 sw48

        sw65 =
            scheduleWord sw63 sw58 sw50 sw49

        sw66 =
            scheduleWord sw64 sw59 sw51 sw50

        sw67 =
            scheduleWord sw65 sw60 sw52 sw51

        sw68 =
            scheduleWord sw66 sw61 sw53 sw52

        sw69 =
            scheduleWord sw67 sw62 sw54 sw53

        sw70 =
            scheduleWord sw68 sw63 sw55 sw54

        sw71 =
            scheduleWord sw69 sw64 sw56 sw55

        sw72 =
            scheduleWord sw70 sw65 sw57 sw56

        sw73 =
            scheduleWord sw71 sw66 sw58 sw57

        sw74 =
            scheduleWord sw72 sw67 sw59 sw58

        sw75 =
            scheduleWord sw73 sw68 sw60 sw59

        sw76 =
            scheduleWord sw74 sw69 sw61 sw60

        sw77 =
            scheduleWord sw75 sw70 sw62 sw61

        sw78 =
            scheduleWord sw76 sw71 sw63 sw62

        sw79 =
            scheduleWord sw77 sw72 sw64 sw63

        s0 =
            { aHi = state.h0h, aLo = state.h0l, bHi = state.h1h, bLo = state.h1l, cHi = state.h2h, cLo = state.h2l, dHi = state.h3h, dLo = state.h3l, eHi = state.h4h, eLo = state.h4l, fHi = state.h5h, fLo = state.h5l, gHi = state.h6h, gLo = state.h6l, hHi = state.h7h, hLo = state.h7l }

        s1 =
            twoRounds 0x428A2F98 0xD728AE22 w0 0x71374491 0x23EF65CD w1 s0

        s2 =
            twoRounds 0xB5C0FBCF 0xEC4D3B2F w2 0xE9B5DBA5 0x8189DBBC w3 s1

        s3 =
            twoRounds 0x3956C25B 0xF348B538 w4 0x59F111F1 0xB605D019 w5 s2

        s4 =
            twoRounds 0x923F82A4 0xAF194F9B w6 0xAB1C5ED5 0xDA6D8118 w7 s3

        s5 =
            twoRounds 0xD807AA98 0xA3030242 w8 0x12835B01 0x45706FBE w9 s4

        s6 =
            twoRounds 0x243185BE 0x4EE4B28C w10 0x550C7DC3 0xD5FFB4E2 w11 s5

        s7 =
            twoRounds 0x72BE5D74 0xF27B896F w12 0x80DEB1FE 0x3B1696B1 w13 s6

        s8 =
            twoRounds 0x9BDC06A7 0x25C71235 w14 0xC19BF174 0xCF692694 w15 s7

        s9 =
            twoRounds 0xE49B69C1 0x9EF14AD2 sw16 0xEFBE4786 0x384F25E3 sw17 s8

        s10 =
            twoRounds 0x0FC19DC6 0x8B8CD5B5 sw18 0x240CA1CC 0x77AC9C65 sw19 s9

        s11 =
            twoRounds 0x2DE92C6F 0x592B0275 sw20 0x4A7484AA 0x6EA6E483 sw21 s10

        s12 =
            twoRounds 0x5CB0A9DC 0xBD41FBD4 sw22 0x76F988DA 0x831153B5 sw23 s11

        s13 =
            twoRounds 0x983E5152 0xEE66DFAB sw24 0xA831C66D 0x2DB43210 sw25 s12

        s14 =
            twoRounds 0xB00327C8 0x98FB213F sw26 0xBF597FC7 0xBEEF0EE4 sw27 s13

        s15 =
            twoRounds 0xC6E00BF3 0x3DA88FC2 sw28 0xD5A79147 0x930AA725 sw29 s14

        s16 =
            twoRounds 0x06CA6351 0xE003826F sw30 0x14292967 0x0A0E6E70 sw31 s15

        s17 =
            twoRounds 0x27B70A85 0x46D22FFC sw32 0x2E1B2138 0x5C26C926 sw33 s16

        s18 =
            twoRounds 0x4D2C6DFC 0x5AC42AED sw34 0x53380D13 0x9D95B3DF sw35 s17

        s19 =
            twoRounds 0x650A7354 0x8BAF63DE sw36 0x766A0ABB 0x3C77B2A8 sw37 s18

        s20 =
            twoRounds 0x81C2C92E 0x47EDAEE6 sw38 0x92722C85 0x1482353B sw39 s19

        s21 =
            twoRounds 0xA2BFE8A1 0x4CF10364 sw40 0xA81A664B 0xBC423001 sw41 s20

        s22 =
            twoRounds 0xC24B8B70 0xD0F89791 sw42 0xC76C51A3 0x0654BE30 sw43 s21

        s23 =
            twoRounds 0xD192E819 0xD6EF5218 sw44 0xD6990624 0x5565A910 sw45 s22

        s24 =
            twoRounds 0xF40E3585 0x5771202A sw46 0x106AA070 0x32BBD1B8 sw47 s23

        s25 =
            twoRounds 0x19A4C116 0xB8D2D0C8 sw48 0x1E376C08 0x5141AB53 sw49 s24

        s26 =
            twoRounds 0x2748774C 0xDF8EEB99 sw50 0x34B0BCB5 0xE19B48A8 sw51 s25

        s27 =
            twoRounds 0x391C0CB3 0xC5C95A63 sw52 0x4ED8AA4A 0xE3418ACB sw53 s26

        s28 =
            twoRounds 0x5B9CCA4F 0x7763E373 sw54 0x682E6FF3 0xD6B2B8A3 sw55 s27

        s29 =
            twoRounds 0x748F82EE 0x5DEFB2FC sw56 0x78A5636F 0x43172F60 sw57 s28

        s30 =
            twoRounds 0x84C87814 0xA1F0AB72 sw58 0x8CC70208 0x1A6439EC sw59 s29

        s31 =
            twoRounds 0x90BEFFFA 0x23631E28 sw60 0xA4506CEB 0xDE82BDE9 sw61 s30

        s32 =
            twoRounds 0xBEF9A3F7 0xB2C67915 sw62 0xC67178F2 0xE372532B sw63 s31

        s33 =
            twoRounds 0xCA273ECE 0xEA26619C sw64 0xD186B8C7 0x21C0C207 sw65 s32

        s34 =
            twoRounds 0xEADA7DD6 0xCDE0EB1E sw66 0xF57D4F7F 0xEE6ED178 sw67 s33

        s35 =
            twoRounds 0x06F067AA 0x72176FBA sw68 0x0A637DC5 0xA2C898A6 sw69 s34

        s36 =
            twoRounds 0x113F9804 0xBEF90DAE sw70 0x1B710B35 0x131C471B sw71 s35

        s37 =
            twoRounds 0x28DB77F5 0x23047D84 sw72 0x32CAAB7B 0x40C72493 sw73 s36

        s38 =
            twoRounds 0x3C9EBE0A 0x15C9BEBC sw74 0x431D67C4 0x9C100D4C sw75 s37

        s39 =
            twoRounds 0x4CC5D4BE 0xCB3E42B6 sw76 0x597F299C 0xFC657E2A sw77 s38

        s40 =
            twoRounds 0x5FCB6FAB 0x3AD6FAEC sw78 0x6C44198C 0x4A475817 sw79 s39

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



-- SHA-512 sigma helper functions


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
