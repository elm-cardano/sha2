module TestSha512 exposing (spec)

import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Expect
import Hex
import SHA512
import Test exposing (..)


toHex : SHA512.Digest -> String
toHex digest =
    digest
        |> SHA512.toBytes
        |> Hex.fromBytes


spec : Test
spec =
    describe "SHA-512 tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    Encode.encode (Encode.string "abc")
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ]
        , describe "spec example 2"
            [ test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" <|
                \_ ->
                    Encode.encode (Encode.string "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            ]
        , describe "empty string"
            [ test "empty" <|
                \_ ->
                    Encode.encode (Encode.sequence [])
                        |> SHA512.fromBytes
                        |> toHex
                        |> Expect.equal "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ]
        ]
