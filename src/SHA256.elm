module SHA256 exposing
    ( Digest
    , fromString, fromBytes, fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-256] is a [cryptographic hash function] that gives 128 bits of security.

[SHA-256]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromString, fromBytes, fromByteValues


# Formatting digests

@docs toHex, toBase64


# To binary data

@docs toBytes, toByteValues

-}

import Base64
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Hex
import Internal.Helper exposing (wordToBytes)
import Internal.SHA256


{-| An abstract sha256 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int Int


initialState : Internal.SHA256.HashResult
initialState =
    { h0 = 0x6A09E667
    , h1 = 0xBB67AE85
    , h2 = 0x3C6EF372
    , h3 = 0xA54FF53A
    , h4 = 0x510E527F
    , h5 = 0x9B05688C
    , h6 = 0x1F83D9AB
    , h7 = 0x5BE0CD19
    }


{-| Create a digest from a `String`.

    import SHA256

    SHA256.fromString "hello world"
        |> SHA256.toHex
    --> "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

-}
fromString : String -> Digest
fromString str =
    fromBytes (Encode.encode (Encode.string str))


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).

    import Bytes.Encode as Encode exposing (Endianness(..))
    import SHA256

    Encode.unsignedInt32 Encode.BE 42
        |> Encode.encode
        |> SHA256.fromBytes
        |> SHA256.toHex
    --> "ae3c8b8d99a39542f78af83dbbb42c81cd94199ec1b5f60a0801063e95842570"

-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        r : Internal.SHA256.HashResult
        r =
            Internal.SHA256.hash initialState bytes
    in
    Digest r.h0 r.h1 r.h2 r.h3 r.h4 r.h5 r.h6 r.h7


{-| Create a digest from a list of byte values (0-255).

    import SHA256

    SHA256.fromByteValues [ 72, 105, 33, 32, 240, 159, 152, 132 ]
        == SHA256.fromString "Hi! \u{1F604}"
    --> True

-}
fromByteValues : List Int -> Digest
fromByteValues values =
    fromBytes (Encode.encode (Encode.sequence (List.map Encode.unsignedInt8 values)))


{-| Turn a digest into a hex string.

    import SHA256

    SHA256.fromString "And our friends are all aboard"
        |> SHA256.toHex
    --> "a40bc1de58430a446e4b446a722fdfd493375c93bf93b1066793909f717da796"

-}
toHex : Digest -> String
toHex (Digest h0 h1 h2 h3 h4 h5 h6 h7) =
    Hex.fromWord32 h0 ++ Hex.fromWord32 h1 ++ Hex.fromWord32 h2 ++ Hex.fromWord32 h3 ++ Hex.fromWord32 h4 ++ Hex.fromWord32 h5 ++ Hex.fromWord32 h6 ++ Hex.fromWord32 h7 ++ ""


{-| Turn a digest into a base64 encoded string.

    import SHA256

    SHA256.fromString "Many more of them live next door"
        |> SHA256.toBase64
    --> "1ov4iAbzsCXuC2R9heu+y57YF/Seb5Vu8cRvVyEY6jM="

-}
toBase64 : Digest -> String
toBase64 digest =
    Base64.fromBytes (toBytes digest)


{-| Turn a digest into `Bytes`. The width is 32 bytes or 256 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest h0 h1 h2 h3 h4 h5 h6 h7) =
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE h0
            , Encode.unsignedInt32 BE h1
            , Encode.unsignedInt32 BE h2
            , Encode.unsignedInt32 BE h3
            , Encode.unsignedInt32 BE h4
            , Encode.unsignedInt32 BE h5
            , Encode.unsignedInt32 BE h6
            , Encode.unsignedInt32 BE h7
            ]
        )


{-| Turn a digest into a list of byte values (0-255).

    import SHA256

    SHA256.fromString "And the band begins to play"
        |> SHA256.toByteValues
    --> [ 0xb1, 0x13, 0x61, 0x72, 0xce, 0xf9, 0x6d, 0xe6
    --> , 0xf0, 0x61, 0x58, 0xd1, 0x43, 0x34, 0x32, 0xaa
    --> , 0xaf, 0xe7, 0x68, 0x0f, 0xd3, 0xb4, 0x6f, 0x55
    --> , 0x92, 0xcd, 0xed, 0xb3, 0x3a, 0xf5, 0x7a, 0x50
    --> ]

-}
toByteValues : Digest -> List Int
toByteValues (Digest h0 h1 h2 h3 h4 h5 h6 h7) =
    List.concatMap wordToBytes [ h0, h1, h2, h3, h4, h5, h6, h7 ]
