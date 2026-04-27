module CrossCheckTest exposing (spec)

import Bitwise
import Bytes exposing (Bytes)
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Expect
import SHA256
import SHA256.V1
import Test exposing (..)


spec : Test
spec =
    describe "V1 vs V2 cross-check"
        [ describe "various input sizes"
            (List.map crossCheck
                [ 0
                , 1
                , 3
                , 55
                , 56
                , 64
                , 65
                , 100
                , 128
                , 256
                , 512
                , 1024
                , 4096
                ]
            )
        ]


crossCheck : Int -> Test
crossCheck n =
    test (String.fromInt n ++ " bytes") <|
        \_ ->
            let
                input =
                    makeBytes n

                v1 =
                    SHA256.V1.hash input

                v2 =
                    SHA256.fromBytes input |> SHA256.toBytes
            in
            bytesToHex v2
                |> Expect.equal (bytesToHex v1)



-- Helpers


makeBytes : Int -> Bytes
makeBytes n =
    Encode.encode
        (Encode.sequence
            (List.map (\i -> Encode.unsignedInt8 (modBy 256 i)) (List.range 0 (n - 1)))
        )


bytesToHex : Bytes -> String
bytesToHex bytes =
    case Decode.decode (bytesToHexDecoder (Bytes.width bytes)) bytes of
        Just hex ->
            hex

        Nothing ->
            ""


bytesToHexDecoder : Int -> Decoder String
bytesToHexDecoder width =
    Decode.loop ( width, "" ) bytesToHexStep


bytesToHexStep : ( Int, String ) -> Decoder (Step ( Int, String ) String)
bytesToHexStep ( remaining, acc ) =
    if remaining <= 0 then
        Decode.succeed (Done acc)

    else
        Decode.unsignedInt8
            |> Decode.map
                (\byte ->
                    Loop ( remaining - 1, acc ++ byteToHex byte )
                )


byteToHex : Int -> String
byteToHex byte =
    String.fromList
        [ nibbleToChar (Bitwise.shiftRightZfBy 4 byte)
        , nibbleToChar (Bitwise.and 0x0F byte)
        ]


nibbleToChar : Int -> Char
nibbleToChar n =
    case n of
        0 ->
            '0'

        1 ->
            '1'

        2 ->
            '2'

        3 ->
            '3'

        4 ->
            '4'

        5 ->
            '5'

        6 ->
            '6'

        7 ->
            '7'

        8 ->
            '8'

        9 ->
            '9'

        10 ->
            'a'

        11 ->
            'b'

        12 ->
            'c'

        13 ->
            'd'

        14 ->
            'e'

        _ ->
            'f'
