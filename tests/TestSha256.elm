module TestSha256 exposing (spec)

import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Expect
import Hex
import SHA256
import Test exposing (..)


toHex : SHA256.Digest -> String
toHex digest =
    digest
        |> SHA256.toBytes
        |> Hex.fromBytes


spec : Test
spec =
    describe "tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    Encode.encode (Encode.string "abc")
                        |> SHA256.fromBytes
                        |> toHex
                        |> Expect.equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ]
        , describe "spec example 2"
            [ test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" <|
                \_ ->
                    Encode.encode (Encode.string "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
                        |> SHA256.fromBytes
                        |> toHex
                        |> Expect.equal "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            ]
        , describe "spec example 3"
            [ test "1 000 000 as" <|
                \_ ->
                    List.repeat (1000000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> toHex
                        |> Expect.equal "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            , test "2 000 000 as" <|
                \_ ->
                    List.repeat (2000000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> toHex
                        |> Expect.equal "bcf7f9d1b4311c3352e60502255ce09a6744df84e8f2c89f79c4b5d74933a95a"
            , test "100 000 as" <|
                \_ ->
                    List.repeat (100000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> toHex
                        |> Expect.equal "6d1cf22d7cc09b085dfc25ee1a1f3ae0265804c607bc2074ad253bcc82fd81ee"
            ]
        , test "custom long string" <|
            \_ ->
                Encode.encode (Encode.string "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqgalkjgkjdsfkjdfk3i3i3ij")
                    |> SHA256.fromBytes
                    |> toHex
                    |> Expect.equal "bd7ef93f08304fe70fef14aa9fadfd325ad88331d78f23516b7ff826d339cd8b"
        ]
