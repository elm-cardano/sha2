module TestSha512 exposing (spec)

import Bytes exposing (Endianness(..))
import Bytes.Encode as Encode
import Expect
import Hex
import SHA512
import Test exposing (Test, describe, test)


longMessage : String
longMessage =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"


toHex : SHA512.Digest -> String
toHex digest =
    digest
        |> SHA512.toBytes
        |> Hex.fromBytes


spec : Test
spec =
    describe "SHA-512 tests from the spec"
        [ describe "spec example 1"
            [ test "abc (fromBytes)" <|
                \_ ->
                    Encode.encode (Encode.string "abc")
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            , test "abc (fromString)" <|
                \_ ->
                    "abc"
                        |> SHA512.fromString
                        |> SHA512.toHex
                        |> Expect.equal "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ]
        , describe "spec example 2"
            [ test "long alphabet message (fromBytes)" <|
                \_ ->
                    Encode.encode (Encode.string longMessage)
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            , test "long alphabet message (fromString)" <|
                \_ ->
                    longMessage
                        |> SHA512.fromString
                        |> SHA512.toHex
                        |> Expect.equal "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            ]
        , describe "spec example 3"
            [ test "1 000 000 as" <|
                \_ ->
                    List.repeat (1000000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            ]
        , describe "empty string"
            [ test "empty (fromBytes)" <|
                \_ ->
                    Encode.encode (Encode.sequence [])
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            , test "empty (fromString)" <|
                \_ ->
                    ""
                        |> SHA512.fromString
                        |> SHA512.toHex
                        |> Expect.equal "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ]
        , describe "Base64 output"
            [ test "abc" <|
                \_ ->
                    "abc"
                        |> SHA512.fromString
                        |> SHA512.toBase64
                        |> Expect.equal "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
            , test "empty" <|
                \_ ->
                    ""
                        |> SHA512.fromString
                        |> SHA512.toBase64
                        |> Expect.equal "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
            ]
        , describe "toByteValues"
            [ test "abc length is 64" <|
                \_ ->
                    "abc"
                        |> SHA512.fromString
                        |> SHA512.toByteValues
                        |> List.length
                        |> Expect.equal 64
            , test "toByteValues matches toBytes" <|
                \_ ->
                    let
                        digest =
                            SHA512.fromString "abc"

                        viaValues =
                            digest
                                |> SHA512.toByteValues
                                |> List.map (\b -> Encode.unsignedInt8 b)
                                |> Encode.sequence
                                |> Encode.encode
                                |> Hex.fromBytes
                    in
                    viaValues
                        |> Expect.equal (toHex digest)
            ]
        ]
