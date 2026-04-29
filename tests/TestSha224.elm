module TestSha224 exposing (spec)

import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Expect
import Hex
import SHA224
import Test exposing (..)


toHex : SHA224.Digest -> String
toHex digest =
    digest
        |> SHA224.toBytes
        |> Hex.fromBytes


spec : Test
spec =
    describe "SHA-224 tests from the spec"
        [ describe "spec example 1"
            [ test "abc (fromString)" <|
                \_ ->
                    "abc"
                        |> SHA224.fromString
                        |> SHA224.toHex
                        |> Expect.equal "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
            , test "abc (fromBytes)" <|
                \_ ->
                    Encode.encode (Encode.string "abc")
                        |> SHA224.fromBytes
                        |> toHex
                        |> Expect.equal "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
            ]
        , describe "spec example 2"
            [ test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" <|
                \_ ->
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                        |> SHA224.fromString
                        |> SHA224.toHex
                        |> Expect.equal "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
            ]
        , describe "spec example 3"
            [ test "1 000 000 'a'" <|
                \_ ->
                    List.repeat 1000000 (Encode.unsignedInt8 0x61)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA224.fromBytes
                        |> SHA224.toHex
                        |> Expect.equal "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
            ]
        , describe "empty string"
            [ test "empty" <|
                \_ ->
                    ""
                        |> SHA224.fromString
                        |> SHA224.toHex
                        |> Expect.equal "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
            ]
        , describe "fromString and fromBytes agree"
            [ test "abc" <|
                \_ ->
                    let
                        viaString =
                            SHA224.toHex (SHA224.fromString "abc")

                        viaBytes =
                            toHex (SHA224.fromBytes (Encode.encode (Encode.string "abc")))
                    in
                    viaString |> Expect.equal viaBytes
            ]
        ]
