module SHA512.V1 exposing (hash)

{-| Straightforward SHA-512 implementation for benchmarking baseline.
Uses W64 records, Array.get for round constants, and recursive helpers.
-}

import Array exposing (Array)
import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode


type alias W64 =
    { hi : Int, lo : Int }


type alias State =
    { h0 : W64, h1 : W64, h2 : W64, h3 : W64, h4 : W64, h5 : W64, h6 : W64, h7 : W64 }


hash : Bytes -> Bytes
hash bytes =
    let
        state =
            hashBytes initialState bytes
    in
    Encode.encode
        (Encode.sequence
            [ encodeW64 state.h0
            , encodeW64 state.h1
            , encodeW64 state.h2
            , encodeW64 state.h3
            , encodeW64 state.h4
            , encodeW64 state.h5
            , encodeW64 state.h6
            , encodeW64 state.h7
            ]
        )


encodeW64 : W64 -> Encode.Encoder
encodeW64 w =
    Encode.sequence
        [ Encode.unsignedInt32 BE (unsigned w.hi)
        , Encode.unsignedInt32 BE (unsigned w.lo)
        ]


initialState : State
initialState =
    { h0 = W64 0x6A09E667 0xF3BCC908
    , h1 = W64 0xBB67AE85 0x84CAA73B
    , h2 = W64 0x3C6EF372 0xFE94F82B
    , h3 = W64 0xA54FF53A 0x5F1D36F1
    , h4 = W64 0x510E527F 0xADE682D1
    , h5 = W64 0x9B05688C 0x2B3E6C1F
    , h6 = W64 0x1F83D9AB 0xFB41BD6B
    , h7 = W64 0x5BE0CD19 0x137E2179
    }


hashBytes : State -> Bytes -> State
hashBytes state bytes =
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

        message =
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

        numberOfChunks =
            Bytes.width message // 128
    in
    case Decode.decode (iterate numberOfChunks reduceBlock state) message of
        Just s ->
            { h0 = unsignedW64 s.h0
            , h1 = unsignedW64 s.h1
            , h2 = unsignedW64 s.h2
            , h3 = unsignedW64 s.h3
            , h4 = unsignedW64 s.h4
            , h5 = unsignedW64 s.h5
            , h6 = unsignedW64 s.h6
            , h7 = unsignedW64 s.h7
            }

        Nothing ->
            state


reduceBlock : State -> Decoder State
reduceBlock state =
    Decode.map4 (\o1 o2 o3 o4 -> processBlock state o1 o2 o3 o4)
        octetDecoder
        octetDecoder
        octetDecoder
        octetDecoder


type alias Octet =
    { a : Int, b : Int, c : Int, d : Int, e : Int, f : Int, g : Int, h : Int }


octetDecoder : Decoder Octet
octetDecoder =
    Decode.map4 (\partial f g h -> partial f g h)
        (Decode.map5 (\a b c d e -> \f g h -> Octet a b c d e f g h) u32 u32 u32 u32 u32)
        u32
        u32
        u32


processBlock : State -> Octet -> Octet -> Octet -> Octet -> State
processBlock state o1 o2 o3 o4 =
    let
        -- Build initial 16-word schedule as Array of W64
        -- Each Octet has 8 u32 fields = 4 W64 words; 4 Octets = 16 W64 words
        schedule =
            Array.fromList
                [ W64 o1.a o1.b, W64 o1.c o1.d, W64 o1.e o1.f, W64 o1.g o1.h
                , W64 o2.a o2.b, W64 o2.c o2.d, W64 o2.e o2.f, W64 o2.g o2.h
                , W64 o3.a o3.b, W64 o3.c o3.d, W64 o3.e o3.f, W64 o3.g o3.h
                , W64 o4.a o4.b, W64 o4.c o4.d, W64 o4.e o4.f, W64 o4.g o4.h
                ]

        -- Expand to 80 words
        fullSchedule =
            expandSchedule 16 schedule

        -- Run 80 rounds
        final =
            runRounds 0 fullSchedule state.h0 state.h1 state.h2 state.h3 state.h4 state.h5 state.h6 state.h7
    in
    { h0 = add64 state.h0 final.h0
    , h1 = add64 state.h1 final.h1
    , h2 = add64 state.h2 final.h2
    , h3 = add64 state.h3 final.h3
    , h4 = add64 state.h4 final.h4
    , h5 = add64 state.h5 final.h5
    , h6 = add64 state.h6 final.h6
    , h7 = add64 state.h7 final.h7
    }


expandSchedule : Int -> Array W64 -> Array W64
expandSchedule i arr =
    if i >= 80 then
        arr

    else
        let
            w2 =
                arrayGet (i - 2) arr

            w7 =
                arrayGet (i - 7) arr

            w15 =
                arrayGet (i - 15) arr

            w16 =
                arrayGet (i - 16) arr

            newW =
                add64 (add64 (ssig1 w2) w7) (add64 (ssig0 w15) w16)
        in
        expandSchedule (i + 1) (Array.push newW arr)


runRounds : Int -> Array W64 -> W64 -> W64 -> W64 -> W64 -> W64 -> W64 -> W64 -> W64 -> State
runRounds i schedule a b c d e f g h =
    if i >= 80 then
        { h0 = a, h1 = b, h2 = c, h3 = d, h4 = e, h5 = f, h6 = g, h7 = h }

    else
        let
            k =
                arrayGet i ks

            w =
                arrayGet i schedule

            ch_ =
                ch e f g

            maj_ =
                maj a b c

            s1 =
                bsig1 e

            s0 =
                bsig0 a

            t1 =
                add64 (add64 (add64 (add64 h s1) ch_) k) w

            t2 =
                add64 s0 maj_
        in
        runRounds (i + 1) schedule (add64 t1 t2) a b c (add64 d t1) e f g


arrayGet : Int -> Array W64 -> W64
arrayGet i arr =
    case Array.get i arr of
        Just v ->
            v

        Nothing ->
            W64 0 0



-- 64-bit operations


add64 : W64 -> W64 -> W64
add64 a b =
    let
        loSum =
            unsigned a.lo + unsigned b.lo
    in
    { hi = a.hi + b.hi + loSum // 4294967296 |> unsigned
    , lo = unsigned loSum
    }


xor64 : W64 -> W64 -> W64
xor64 a b =
    { hi = Bitwise.xor a.hi b.hi, lo = Bitwise.xor a.lo b.lo }


and64 : W64 -> W64 -> W64
and64 a b =
    { hi = Bitwise.and a.hi b.hi, lo = Bitwise.and a.lo b.lo }


not64 : W64 -> W64
not64 a =
    { hi = Bitwise.complement a.hi, lo = Bitwise.complement a.lo }


rotr64 : Int -> W64 -> W64
rotr64 n w =
    if n < 32 then
        { hi = Bitwise.or (Bitwise.shiftRightZfBy n w.hi) (Bitwise.shiftLeftBy (32 - n) w.lo)
        , lo = Bitwise.or (Bitwise.shiftRightZfBy n w.lo) (Bitwise.shiftLeftBy (32 - n) w.hi)
        }

    else
        let
            m =
                n - 32
        in
        { hi = Bitwise.or (Bitwise.shiftRightZfBy m w.lo) (Bitwise.shiftLeftBy (32 - m) w.hi)
        , lo = Bitwise.or (Bitwise.shiftRightZfBy m w.hi) (Bitwise.shiftLeftBy (32 - m) w.lo)
        }


shr64 : Int -> W64 -> W64
shr64 n w =
    if n < 32 then
        { hi = Bitwise.shiftRightZfBy n w.hi
        , lo = Bitwise.or (Bitwise.shiftRightZfBy n w.lo) (Bitwise.shiftLeftBy (32 - n) w.hi)
        }

    else
        { hi = 0
        , lo = Bitwise.shiftRightZfBy (n - 32) w.hi
        }


unsignedW64 : W64 -> W64
unsignedW64 w =
    { hi = unsigned w.hi, lo = unsigned w.lo }



-- SHA-512 functions


ch : W64 -> W64 -> W64 -> W64
ch e f g =
    xor64 (and64 e f) (and64 (not64 e) g)


maj : W64 -> W64 -> W64 -> W64
maj a b c =
    xor64 (xor64 (and64 a b) (and64 a c)) (and64 b c)


bsig0 : W64 -> W64
bsig0 x =
    xor64 (xor64 (rotr64 28 x) (rotr64 34 x)) (rotr64 39 x)


bsig1 : W64 -> W64
bsig1 x =
    xor64 (xor64 (rotr64 14 x) (rotr64 18 x)) (rotr64 41 x)


ssig0 : W64 -> W64
ssig0 x =
    xor64 (xor64 (rotr64 1 x) (rotr64 8 x)) (shr64 7 x)


ssig1 : W64 -> W64
ssig1 x =
    xor64 (xor64 (rotr64 19 x) (rotr64 61 x)) (shr64 6 x)


unsigned : Int -> Int
unsigned x =
    Bitwise.shiftRightZfBy 0 x



-- Helpers


u32 : Decoder Int
u32 =
    Decode.unsignedInt32 BE


iterate : Int -> (a -> Decoder a) -> a -> Decoder a
iterate n step initial =
    Decode.loop ( n, initial ) (loopHelp step)


loopHelp : (a -> Decoder a) -> ( Int, a ) -> Decoder (Step ( Int, a ) a)
loopHelp step ( n, state ) =
    if n > 0 then
        step state
            |> Decode.map (\new -> Decode.Loop ( n - 1, new ))

    else
        Decode.succeed (Decode.Done state)



-- Round constants


ks : Array W64
ks =
    Array.fromList
        [ W64 0x428A2F98 0xD728AE22, W64 0x71374491 0x23EF65CD, W64 0xB5C0FBCF 0xEC4D3B2F, W64 0xE9B5DBA5 0x8189DBBC
        , W64 0x3956C25B 0xF348B538, W64 0x59F111F1 0xB605D019, W64 0x923F82A4 0xAF194F9B, W64 0xAB1C5ED5 0xDA6D8118
        , W64 0xD807AA98 0xA3030242, W64 0x12835B01 0x45706FBE, W64 0x243185BE 0x4EE4B28C, W64 0x550C7DC3 0xD5FFB4E2
        , W64 0x72BE5D74 0xF27B896F, W64 0x80DEB1FE 0x3B1696B1, W64 0x9BDC06A7 0x25C71235, W64 0xC19BF174 0xCF692694
        , W64 0xE49B69C1 0x9EF14AD2, W64 0xEFBE4786 0x384F25E3, W64 0x0FC19DC6 0x8B8CD5B5, W64 0x240CA1CC 0x77AC9C65
        , W64 0x2DE92C6F 0x592B0275, W64 0x4A7484AA 0x6EA6E483, W64 0x5CB0A9DC 0xBD41FBD4, W64 0x76F988DA 0x831153B5
        , W64 0x983E5152 0xEE66DFAB, W64 0xA831C66D 0x2DB43210, W64 0xB00327C8 0x98FB213F, W64 0xBF597FC7 0xBEEF0EE4
        , W64 0xC6E00BF3 0x3DA88FC2, W64 0xD5A79147 0x930AA725, W64 0x06CA6351 0xE003826F, W64 0x14292967 0x0A0E6E70
        , W64 0x27B70A85 0x46D22FFC, W64 0x2E1B2138 0x5C26C926, W64 0x4D2C6DFC 0x5AC42AED, W64 0x53380D13 0x9D95B3DF
        , W64 0x650A7354 0x8BAF63DE, W64 0x766A0ABB 0x3C77B2A8, W64 0x81C2C92E 0x47EDAEE6, W64 0x92722C85 0x1482353B
        , W64 0xA2BFE8A1 0x4CF10364, W64 0xA81A664B 0xBC423001, W64 0xC24B8B70 0xD0F89791, W64 0xC76C51A3 0x0654BE30
        , W64 0xD192E819 0xD6EF5218, W64 0xD6990624 0x5565A910, W64 0xF40E3585 0x5771202A, W64 0x106AA070 0x32BBD1B8
        , W64 0x19A4C116 0xB8D2D0C8, W64 0x1E376C08 0x5141AB53, W64 0x2748774C 0xDF8EEB99, W64 0x34B0BCB5 0xE19B48A8
        , W64 0x391C0CB3 0xC5C95A63, W64 0x4ED8AA4A 0xE3418ACB, W64 0x5B9CCA4F 0x7763E373, W64 0x682E6FF3 0xD6B2B8A3
        , W64 0x748F82EE 0x5DEFB2FC, W64 0x78A5636F 0x43172F60, W64 0x84C87814 0xA1F0AB72, W64 0x8CC70208 0x1A6439EC
        , W64 0x90BEFFFA 0x23631E28, W64 0xA4506CEB 0xDE82BDE9, W64 0xBEF9A3F7 0xB2C67915, W64 0xC67178F2 0xE372532B
        , W64 0xCA273ECE 0xEA26619C, W64 0xD186B8C7 0x21C0C207, W64 0xEADA7DD6 0xCDE0EB1E, W64 0xF57D4F7F 0xEE6ED178
        , W64 0x06F067AA 0x72176FBA, W64 0x0A637DC5 0xA2C898A6, W64 0x113F9804 0xBEF90DAE, W64 0x1B710B35 0x131C471B
        , W64 0x28DB77F5 0x23047D84, W64 0x32CAAB7B 0x40C72493, W64 0x3C9EBE0A 0x15C9BEBC, W64 0x431D67C4 0x9C100D4C
        , W64 0x4CC5D4BE 0xCB3E42B6, W64 0x597F299C 0xFC657E2A, W64 0x5FCB6FAB 0x3AD6FAEC, W64 0x6C44198C 0x4A475817
        ]
