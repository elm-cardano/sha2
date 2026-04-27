module Internal.Base64 exposing (encode)

import Bitwise
import Bytes exposing (Bytes)
import Bytes.Decode as Decode exposing (Decoder, Step(..))


encode : Bytes -> String
encode bytes =
    let
        width =
            Bytes.width bytes
    in
    case Decode.decode (base64Decoder width) bytes of
        Just result ->
            result

        Nothing ->
            ""


base64Decoder : Int -> Decoder String
base64Decoder totalBytes =
    Decode.loop { remaining = totalBytes, acc = "" } base64Step


base64Step : { remaining : Int, acc : String } -> Decoder (Step { remaining : Int, acc : String } String)
base64Step { remaining, acc } =
    if remaining >= 3 then
        Decode.map3
            (\b0 b1 b2 ->
                let
                    n =
                        Bitwise.or (Bitwise.or (Bitwise.shiftLeftBy 16 b0) (Bitwise.shiftLeftBy 8 b1)) b2
                in
                Loop
                    { remaining = remaining - 3
                    , acc =
                        acc
                            ++ String.fromList
                                [ base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 18 n))
                                , base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 12 n))
                                , base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 6 n))
                                , base64Char (Bitwise.and 0x3F n)
                                ]
                    }
            )
            Decode.unsignedInt8
            Decode.unsignedInt8
            Decode.unsignedInt8

    else if remaining == 2 then
        Decode.map2
            (\b0 b1 ->
                let
                    n =
                        Bitwise.or (Bitwise.shiftLeftBy 16 b0) (Bitwise.shiftLeftBy 8 b1)
                in
                Done
                    (acc
                        ++ String.fromList
                            [ base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 18 n))
                            , base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 12 n))
                            , base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 6 n))
                            , '='
                            ]
                    )
            )
            Decode.unsignedInt8
            Decode.unsignedInt8

    else if remaining == 1 then
        Decode.map
            (\b0 ->
                let
                    n =
                        Bitwise.shiftLeftBy 16 b0
                in
                Done
                    (acc
                        ++ String.fromList
                            [ base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 18 n))
                            , base64Char (Bitwise.and 0x3F (Bitwise.shiftRightZfBy 12 n))
                            , '='
                            , '='
                            ]
                    )
            )
            Decode.unsignedInt8

    else
        Decode.succeed (Done acc)


base64Char : Int -> Char
base64Char n =
    case n of
        0 ->
            'A'

        1 ->
            'B'

        2 ->
            'C'

        3 ->
            'D'

        4 ->
            'E'

        5 ->
            'F'

        6 ->
            'G'

        7 ->
            'H'

        8 ->
            'I'

        9 ->
            'J'

        10 ->
            'K'

        11 ->
            'L'

        12 ->
            'M'

        13 ->
            'N'

        14 ->
            'O'

        15 ->
            'P'

        16 ->
            'Q'

        17 ->
            'R'

        18 ->
            'S'

        19 ->
            'T'

        20 ->
            'U'

        21 ->
            'V'

        22 ->
            'W'

        23 ->
            'X'

        24 ->
            'Y'

        25 ->
            'Z'

        26 ->
            'a'

        27 ->
            'b'

        28 ->
            'c'

        29 ->
            'd'

        30 ->
            'e'

        31 ->
            'f'

        32 ->
            'g'

        33 ->
            'h'

        34 ->
            'i'

        35 ->
            'j'

        36 ->
            'k'

        37 ->
            'l'

        38 ->
            'm'

        39 ->
            'n'

        40 ->
            'o'

        41 ->
            'p'

        42 ->
            'q'

        43 ->
            'r'

        44 ->
            's'

        45 ->
            't'

        46 ->
            'u'

        47 ->
            'v'

        48 ->
            'w'

        49 ->
            'x'

        50 ->
            'y'

        51 ->
            'z'

        52 ->
            '0'

        53 ->
            '1'

        54 ->
            '2'

        55 ->
            '3'

        56 ->
            '4'

        57 ->
            '5'

        58 ->
            '6'

        59 ->
            '7'

        60 ->
            '8'

        61 ->
            '9'

        62 ->
            '+'

        _ ->
            '/'
