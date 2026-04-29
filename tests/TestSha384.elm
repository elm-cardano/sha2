module TestSha384 exposing (spec)

import Bytes.Encode as Encode
import Expect
import Hex
import SHA384
import Test exposing (Test, describe, test)


longMessage : String
longMessage =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"


toHex : SHA384.Digest -> String
toHex digest =
    digest
        |> SHA384.toBytes
        |> Hex.fromBytes


spec : Test
spec =
    describe "SHA-384 tests from the spec"
        [ describe "spec example 1"
            [ test "abc (fromString)" <|
                \_ ->
                    "abc"
                        |> SHA384.fromString
                        |> SHA384.toHex
                        |> Expect.equal "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            , test "abc (fromBytes)" <|
                \_ ->
                    Encode.encode (Encode.string "abc")
                        |> SHA384.fromBytes
                        |> toHex
                        |> Expect.equal "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            ]
        , describe "spec example 2"
            [ test "long alphabet message" <|
                \_ ->
                    longMessage
                        |> SHA384.fromString
                        |> SHA384.toHex
                        |> Expect.equal "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
            ]
        , describe "empty string"
            [ test "empty" <|
                \_ ->
                    ""
                        |> SHA384.fromString
                        |> SHA384.toHex
                        |> Expect.equal "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            ]
        , describe "fromString and fromBytes agree"
            [ test "long alphabet message" <|
                \_ ->
                    let
                        viaString : String
                        viaString =
                            SHA384.toHex (SHA384.fromString longMessage)

                        viaBytes : String
                        viaBytes =
                            toHex (SHA384.fromBytes (Encode.encode (Encode.string longMessage)))
                    in
                    viaString |> Expect.equal viaBytes
            ]
        ]
