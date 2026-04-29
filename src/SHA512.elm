module SHA512 exposing
    ( Digest
    , fromString, fromBytes, fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-512] is a [cryptographic hash function] that gives 256 bits of security.

[SHA-512]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
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
import Internal.SHA512


{-| An abstract sha512 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int Int Int Int Int Int Int Int Int Int


initialState : Internal.SHA512.HashResult
initialState =
    { h0h = 0x6A09E667
    , h0l = 0xF3BCC908
    , h1h = 0xBB67AE85
    , h1l = 0x84CAA73B
    , h2h = 0x3C6EF372
    , h2l = 0xFE94F82B
    , h3h = 0xA54FF53A
    , h3l = 0x5F1D36F1
    , h4h = 0x510E527F
    , h4l = 0xADE682D1
    , h5h = 0x9B05688C
    , h5l = 0x2B3E6C1F
    , h6h = 0x1F83D9AB
    , h6l = 0xFB41BD6B
    , h7h = 0x5BE0CD19
    , h7l = 0x137E2179
    }


{-| Create a digest from a `String`.

    import SHA512

    SHA512.fromString "hello world"
        |> SHA512.toHex
    --> "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"

-}
fromString : String -> Digest
fromString str =
    fromBytes (Encode.encode (Encode.string str))


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).

    import Bytes.Encode as Encode exposing (Endianness(..))
    import SHA512

    Encode.unsignedInt32 Encode.BE 42
        |> Encode.encode
        |> SHA512.fromBytes
        |> SHA512.toHex
    --> "08cc3f0991969ae44b05e92bcd8f6ece4dd4e9733a9288dcfff47325906c36ecab9a3c63e59411b3df1f6fed6a232c6a20bff3afff91b36689a41037cbe0b6a0"

-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        r =
            Internal.SHA512.hash initialState bytes
    in
    Digest r.h0h r.h0l r.h1h r.h1l r.h2h r.h2l r.h3h r.h3l r.h4h r.h4l r.h5h r.h5l r.h6h r.h6l r.h7h r.h7l


{-| Create a digest from a list of byte values (0-255).

    import SHA512

    SHA512.fromByteValues [ 72, 105, 33, 32, 240, 159, 152, 132 ]
        == SHA512.fromString "Hi! \u{1F604}"
    --> True

-}
fromByteValues : List Int -> Digest
fromByteValues values =
    fromBytes (Encode.encode (Encode.sequence (List.map Encode.unsignedInt8 values)))


{-| Turn a digest into a hex string.

    import SHA512

    SHA512.fromString "And our friends are all aboard"
        |> SHA512.toHex
    --> "5af050bf4b4f2fbb2f032f42521e2e46a1aff6dcd02176c31425d8777abbe5c818375de27fd8d83cd848621a85507d1bd19eb35c70152c0f8e77b9ba3104e669"

-}
toHex : Digest -> String
toHex (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l h6h h6l h7h h7l) =
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
        ++ Hex.fromWord32 h6h
        ++ Hex.fromWord32 h6l
        ++ Hex.fromWord32 h7h
        ++ Hex.fromWord32 h7l
        ++ ""


{-| Turn a digest into a base64 encoded string.

    import SHA512

    SHA512.fromString "Many more of them live next door"
        |> SHA512.toBase64
    --> "cyr6xhwqW4Fk9Gm5R4h/dqFxkPOf/gPHKiI6t00qQFC8QJAP65IlZkS4YhdGxTvL7VPFzlSPAoXtPTxPAmVJrg=="

-}
toBase64 : Digest -> String
toBase64 digest =
    Base64.fromBytes (toBytes digest)


{-| Turn a digest into `Bytes`. The width is 64 bytes or 512 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l h6h h6l h7h h7l) =
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
            , Encode.unsignedInt32 BE h6h
            , Encode.unsignedInt32 BE h6l
            , Encode.unsignedInt32 BE h7h
            , Encode.unsignedInt32 BE h7l
            ]
        )


{-| Turn a digest into a list of byte values (0-255).

    import SHA512

    SHA512.fromString "And the band begins to play"
        |> SHA512.toByteValues
    --> [ 153, 140, 77, 156, 68, 193, 195, 117
    --> , 134, 19, 24, 147, 44, 86, 45, 132
    --> , 106, 110, 43, 98, 221, 233, 100, 27
    --> , 183, 45, 33, 120, 139, 31, 6, 103
    --> , 128, 205, 65, 65, 9, 252, 111, 213
    --> , 5, 60, 65, 56, 181, 170, 166, 85
    --> , 7, 48, 58, 253, 54, 121, 246, 230
    --> , 31, 95, 205, 70, 53, 219, 78, 168
    --> ]

-}
toByteValues : Digest -> List Int
toByteValues (Digest h0h h0l h1h h1l h2h h2l h3h h3l h4h h4l h5h h5l h6h h6l h7h h7l) =
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
        ++ wordToBytes h6h
        ++ wordToBytes h6l
        ++ wordToBytes h7h
        ++ wordToBytes h7l
