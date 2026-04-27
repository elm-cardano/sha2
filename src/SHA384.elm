module SHA384 exposing
    ( Digest
    , fromString, fromBytes, fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-384] is a [cryptographic hash function] that gives 192 bits of security.

It is a truncated variant of SHA-512 with different initial hash values.

[SHA-384]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromString, fromBytes, fromByteValues


# Formatting digests

@docs toHex, toBase64


# To binary data

@docs toBytes, toByteValues

-}

import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Hex
import Internal.Base64
import Internal.Helper exposing (wordToBytes)
import Internal.SHA512


{-| An abstract sha384 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int Int Int Int Int Int


initialState : Internal.SHA512.HashResult
initialState =
    { h0h = 0xCBBB9D5D
    , h0l = 0xC1059ED8
    , h1h = 0x629A292A
    , h1l = 0x367CD507
    , h2h = 0x9159015A
    , h2l = 0x3070DD17
    , h3h = 0x152FECD8
    , h3l = 0xF70E5939
    , h4h = 0x67332667
    , h4l = 0xFFC00B31
    , h5h = 0x8EB44A87
    , h5l = 0x68581511
    , h6h = 0xDB0C2E0D
    , h6l = 0x64F98FA7
    , h7h = 0x47B5481D
    , h7l = 0xBEFA4FA4
    }


{-| Create a digest from a `String`.

    import SHA384

    SHA384.fromString "hello world"
        |> SHA384.toHex
    --> "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"

-}
fromString : String -> Digest
fromString str =
    fromBytes (Encode.encode (Encode.string str))


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).

    import Bytes.Encode as Encode exposing (Endianness(..))
    import SHA384

    Encode.unsignedInt32 Encode.BE 42
        |> Encode.encode
        |> SHA384.fromBytes
        |> SHA384.toHex
    --> "169c6e0f2a73b8a3f0c6dad952ab62ee64136652d1bfcf5901951186384324070819bba50666c9371265b68b7a57410d"

-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        r =
            Internal.SHA512.hash initialState bytes
    in
    Digest r.h0h r.h0l r.h1h r.h1l r.h2h r.h2l r.h3h r.h3l r.h4h r.h4l r.h5h r.h5l


{-| Create a digest from a list of byte values (0-255).

    import SHA384

    SHA384.fromByteValues [ 72, 105, 33, 32, 240, 159, 152, 132 ]
        == SHA384.fromString "Hi! \u{1F604}"
    --> True

-}
fromByteValues : List Int -> Digest
fromByteValues values =
    fromBytes (Encode.encode (Encode.sequence (List.map Encode.unsignedInt8 values)))


{-| Turn a digest into a hex string.

    import SHA384

    SHA384.fromString "And our friends are all aboard"
        |> SHA384.toHex
    --> "8b955c0b596df8b93db7c9a0105098c5be18bd4dbbea4cccf9b4b138c54668d0c9295485dc3b20a1ecd1bf97762f3b47"

-}
toHex : Digest -> String
toHex (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l) =
    Hex.fromWord32 h0h
        ++ Hex.fromWord32 h0l
        ++ Hex.fromWord32 h1h
        ++ Hex.fromWord32 h1l
        ++ Hex.fromWord32 h2h
        ++ Hex.fromWord32 h2l
        ++ Hex.fromWord32 h3h
        ++ Hex.fromWord32 h3l
        ++ Hex.fromWord32 h4h
        ++ Hex.fromWord32 h4l
        ++ Hex.fromWord32 h5h
        ++ Hex.fromWord32 h5l
        ++ ""


{-| Turn a digest into a base64 encoded string.

    import SHA384

    SHA384.fromString "Many more of them live next door"
        |> SHA384.toBase64
    --> "pKq5Z/Msjg14oJ2TGHS21h+L9lMWkASENRmCgur5mpwRNoE3dAPWV6kw+aNX1gmB"

-}
toBase64 : Digest -> String
toBase64 digest =
    Internal.Base64.encode (toBytes digest)


{-| Turn a digest into `Bytes`. The width is 48 bytes or 384 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l) =
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE h0h
            , Encode.unsignedInt32 BE h0l
            , Encode.unsignedInt32 BE h1h
            , Encode.unsignedInt32 BE h1l
            , Encode.unsignedInt32 BE h2h
            , Encode.unsignedInt32 BE h2l
            , Encode.unsignedInt32 BE h3h
            , Encode.unsignedInt32 BE h3l
            , Encode.unsignedInt32 BE h4h
            , Encode.unsignedInt32 BE h4l
            , Encode.unsignedInt32 BE h5h
            , Encode.unsignedInt32 BE h5l
            ]
        )


{-| Turn a digest into a list of byte values (0-255).

    import SHA384

    SHA384.fromString "And the band begins to play"
        |> SHA384.toByteValues
    --> [ 216, 234, 215, 67, 129, 199, 177, 6
    --> , 4, 113, 130, 141, 149, 211, 213, 72
    --> , 182, 77, 43, 191, 48, 162, 210, 207
    --> , 88, 239, 69, 109, 211, 248, 187, 238
    --> , 97, 27, 125, 162, 116, 132, 44, 35
    --> , 116, 33, 51, 81, 115, 241, 201, 137
    --> ]

-}
toByteValues : Digest -> List Int
toByteValues (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l) =
    wordToBytes h0h
        ++ wordToBytes h0l
        ++ wordToBytes h1h
        ++ wordToBytes h1l
        ++ wordToBytes h2h
        ++ wordToBytes h2l
        ++ wordToBytes h3h
        ++ wordToBytes h3l
        ++ wordToBytes h4h
        ++ wordToBytes h4l
        ++ wordToBytes h5h
        ++ wordToBytes h5l
