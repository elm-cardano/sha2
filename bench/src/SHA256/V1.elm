module SHA256.V1 exposing (hash)

{-| Original folkertdev/elm-sha2 implementation, copied here for A/B benchmarking.
-}

import Array
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode



-- CONSTANTS


blockSize : Int
blockSize =
    64


numberOfWords : Int
numberOfWords =
    16



-- TYPES


type Tuple8
    = Tuple8 Int Int Int Int Int Int Int Int


type Digest
    = Digest Tuple8


type State
    = State Tuple8


type DeltaState
    = DeltaState Tuple8



-- PUBLIC API


{-| Hash bytes and return the 32-byte digest as Bytes.
-}
hash : Bytes -> Bytes
hash bytes =
    let
        (Digest (Tuple8 a b c d e f g h)) =
            hashBytes initialState bytes
    in
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE a
            , Encode.unsignedInt32 BE b
            , Encode.unsignedInt32 BE c
            , Encode.unsignedInt32 BE d
            , Encode.unsignedInt32 BE e
            , Encode.unsignedInt32 BE f
            , Encode.unsignedInt32 BE g
            , Encode.unsignedInt32 BE h
            ]
        )


initialState : State
initialState =
    State (Tuple8 0x6A09E667 0xBB67AE85 0x3C6EF372 0xA54FF53A 0x510E527F 0x9B05688C 0x1F83D9AB 0x5BE0CD19)



-- CORE ALGORITHM


padBuffer : Bytes -> Bytes
padBuffer bytes =
    let
        byteCount =
            Bytes.width bytes

        finalBlockSize =
            Bitwise.and byteCount 0x3F

        paddingSize =
            if finalBlockSize < 56 then
                (55 - finalBlockSize) + 4

            else
                (119 - finalBlockSize) + 4

        message =
            Encode.encode
                (Encode.sequence
                    [ Encode.bytes bytes
                    , Encode.unsignedInt8 0x80
                    , Encode.sequence (List.repeat paddingSize (Encode.unsignedInt8 0))
                    , Encode.unsignedInt32 BE (Bitwise.shiftLeftBy 3 byteCount)
                    ]
                )
    in
    message


hashBytes : State -> Bytes -> Digest
hashBytes state bytes =
    let
        message =
            padBuffer bytes

        numberOfChunks : Int
        numberOfChunks =
            Bytes.width message // 64

        hashState : Decoder State
        hashState =
            iterate numberOfChunks reduceBytesMessage state
    in
    case Decode.decode hashState message of
        Just (State (Tuple8 a b c d e f g h)) ->
            Digest
                (Tuple8
                    (Bitwise.shiftRightZfBy 0 a)
                    (Bitwise.shiftRightZfBy 0 b)
                    (Bitwise.shiftRightZfBy 0 c)
                    (Bitwise.shiftRightZfBy 0 d)
                    (Bitwise.shiftRightZfBy 0 e)
                    (Bitwise.shiftRightZfBy 0 f)
                    (Bitwise.shiftRightZfBy 0 g)
                    (Bitwise.shiftRightZfBy 0 h)
                )

        Nothing ->
            case state of
                State tuple8 ->
                    Digest tuple8


u32 : Decoder Int
u32 =
    Decode.unsignedInt32 BE


reduceBytesMessage : State -> Decoder State
reduceBytesMessage state =
    map16 (reduceMessage state) u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32 u32


reduceMessage : State -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> State
reduceMessage (State ((Tuple8 h0 h1 h2 h3 h4 h5 h6 h7) as initial)) b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 =
    let
        initialDeltaState =
            DeltaState initial
                |> calculateDigestDeltas 0 b1
                |> calculateDigestDeltas 1 b2
                |> calculateDigestDeltas 2 b3
                |> calculateDigestDeltas 3 b4
                |> calculateDigestDeltas 4 b5
                |> calculateDigestDeltas 5 b6
                |> calculateDigestDeltas 6 b7
                |> calculateDigestDeltas 7 b8
                |> calculateDigestDeltas 8 b9
                |> calculateDigestDeltas 9 b10
                |> calculateDigestDeltas 10 b11
                |> calculateDigestDeltas 11 b12
                |> calculateDigestDeltas 12 b13
                |> calculateDigestDeltas 13 b14
                |> calculateDigestDeltas 14 b15
                |> calculateDigestDeltas 15 b16

        (DeltaState (Tuple8 a b c d e f g h)) =
            reduceWordsHelp 0 initialDeltaState b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16
    in
    State (Tuple8 (h0 + a) (h1 + b) (h2 + c) (h3 + d) (h4 + e) (h5 + f) (h6 + g) (h7 + h))


reduceWordsHelp : Int -> DeltaState -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> Int -> DeltaState
reduceWordsHelp i deltaState b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    if i < 48 then
        let
            smallSigma0 =
                Bitwise.or (Bitwise.shiftLeftBy (32 - 7) b15) (Bitwise.shiftRightZfBy 7 b15)
                    |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 18) b15) (Bitwise.shiftRightZfBy 18 b15))
                    |> Bitwise.xor (Bitwise.shiftRightZfBy 3 b15)

            smallSigma1 =
                Bitwise.or (Bitwise.shiftLeftBy (32 - 17) b2) (Bitwise.shiftRightZfBy 17 b2)
                    |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 19) b2) (Bitwise.shiftRightZfBy 19 b2))
                    |> Bitwise.xor (Bitwise.shiftRightZfBy 10 b2)

            w =
                (smallSigma1 + b7 + smallSigma0 + b16)
                    |> Bitwise.shiftRightZfBy 0
        in
        reduceWordsHelp (i + 1) (calculateDigestDeltas (i + numberOfWords) w deltaState) b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 w

    else
        deltaState


calculateDigestDeltas : Int -> Int -> DeltaState -> DeltaState
calculateDigestDeltas index w (DeltaState (Tuple8 a b c d e f g h)) =
    let
        ch =
            Bitwise.and e f
                |> Bitwise.xor (Bitwise.and (Bitwise.complement e) g)
                |> Bitwise.shiftRightZfBy 0

        maj =
            Bitwise.and a (Bitwise.xor b c)
                |> Bitwise.xor (Bitwise.and b c)

        k =
            case Array.get index ks of
                Nothing ->
                    0

                Just v ->
                    v

        bigSigma1 =
            Bitwise.or (Bitwise.shiftLeftBy (32 - 6) e) (Bitwise.shiftRightZfBy 6 e)
                |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 11) e) (Bitwise.shiftRightZfBy 11 e))
                |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 25) e) (Bitwise.shiftRightZfBy 25 e))

        t1 =
            h + bigSigma1 + ch + k + w

        bigSigma0 =
            Bitwise.or (Bitwise.shiftLeftBy (32 - 2) a) (Bitwise.shiftRightZfBy 2 a)
                |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 13) a) (Bitwise.shiftRightZfBy 13 a))
                |> Bitwise.xor (Bitwise.or (Bitwise.shiftLeftBy (32 - 22) a) (Bitwise.shiftRightZfBy 22 a))

        t2 =
            bigSigma0 + maj

        newA =
            Bitwise.shiftRightZfBy 0 (t1 + t2)

        newE =
            Bitwise.shiftRightZfBy 0 (d + t1)

        result =
            Tuple8 newA a b c newE e f g
    in
    DeltaState result



-- HELPERS


map16 :
    (b1 -> b2 -> b3 -> b4 -> b5 -> b6 -> b7 -> b8 -> b9 -> b10 -> b11 -> b12 -> b13 -> b14 -> b15 -> b16 -> result)
    -> Decoder b1
    -> Decoder b2
    -> Decoder b3
    -> Decoder b4
    -> Decoder b5
    -> Decoder b6
    -> Decoder b7
    -> Decoder b8
    -> Decoder b9
    -> Decoder b10
    -> Decoder b11
    -> Decoder b12
    -> Decoder b13
    -> Decoder b14
    -> Decoder b15
    -> Decoder b16
    -> Decoder result
map16 f b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 =
    let
        d1 =
            Decode.map4 (\a b c d -> f a b c d) b1 b2 b3 b4

        d2 =
            Decode.map5 (\h a b c d -> h a b c d) d1 b5 b6 b7 b8

        d3 =
            Decode.map5 (\h a b c d -> h a b c d) d2 b9 b10 b11 b12

        d4 =
            Decode.map5 (\h a b c d -> h a b c d) d3 b13 b14 b15 b16
    in
    d4


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


ks : Array.Array Int
ks =
    Array.fromList
        [ 0x428A2F98
        , 0x71374491
        , 0xB5C0FBCF
        , 0xE9B5DBA5
        , 0x3956C25B
        , 0x59F111F1
        , 0x923F82A4
        , 0xAB1C5ED5
        , 0xD807AA98
        , 0x12835B01
        , 0x243185BE
        , 0x550C7DC3
        , 0x72BE5D74
        , 0x80DEB1FE
        , 0x9BDC06A7
        , 0xC19BF174
        , 0xE49B69C1
        , 0xEFBE4786
        , 0x0FC19DC6
        , 0x240CA1CC
        , 0x2DE92C6F
        , 0x4A7484AA
        , 0x5CB0A9DC
        , 0x76F988DA
        , 0x983E5152
        , 0xA831C66D
        , 0xB00327C8
        , 0xBF597FC7
        , 0xC6E00BF3
        , 0xD5A79147
        , 0x06CA6351
        , 0x14292967
        , 0x27B70A85
        , 0x2E1B2138
        , 0x4D2C6DFC
        , 0x53380D13
        , 0x650A7354
        , 0x766A0ABB
        , 0x81C2C92E
        , 0x92722C85
        , 0xA2BFE8A1
        , 0xA81A664B
        , 0xC24B8B70
        , 0xC76C51A3
        , 0xD192E819
        , 0xD6990624
        , 0xF40E3585
        , 0x106AA070
        , 0x19A4C116
        , 0x1E376C08
        , 0x2748774C
        , 0x34B0BCB5
        , 0x391C0CB3
        , 0x4ED8AA4A
        , 0x5B9CCA4F
        , 0x682E6FF3
        , 0x748F82EE
        , 0x78A5636F
        , 0x84C87814
        , 0x8CC70208
        , 0x90BEFFFA
        , 0xA4506CEB
        , 0xBEF9A3F7
        , 0xC67178F2
        ]
