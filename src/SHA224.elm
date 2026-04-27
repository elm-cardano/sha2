module SHA224 exposing
    ( Digest
    , fromString
    , fromBytes
    , fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-224] is a [cryptographic hash function] that gives 112 bits of security.

It is a truncated variant of SHA-256 with different initial hash values.

[SHA-224]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromString, fromBytes, fromByteValues


# Formatting digests

@docs toHex, toBase64


# To binary data

@docs toBytes, toByteValues

-}

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode
import Internal.Base64
import Internal.SHA256


{-| An abstract sha224 digest.
-}
type Digest
    = Digest Int Int Int Int Int Int Int


initialState : Internal.SHA256.HashResult
initialState =
    { h0 = 0xC1059ED8
    , h1 = 0x367CD507
    , h2 = 0x3070DD17
    , h3 = 0xF70E5939
    , h4 = 0xFFC00B31
    , h5 = 0x68581511
    , h6 = 0x64F98FA7
    , h7 = 0xBEFA4FA4
    }


{-| Create a digest from a `String`.

    import SHA224

    SHA224.fromString "hello world"
        |> SHA224.toHex
    --> "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b"

-}
fromString : String -> Digest
fromString str =
    fromBytes (Encode.encode (Encode.string str))


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).

    import Bytes.Encode as Encode exposing (Endianness(..))
    import SHA224

    Encode.unsignedInt32 Encode.BE 42
        |> Encode.encode
        |> SHA224.fromBytes
        |> SHA224.toHex
    --> "793ce43981dc8ea9c80d5518905c629b54dec6c94152e7dbb08a4177"

-}
fromBytes : Bytes -> Digest
fromBytes bytes =
    let
        r =
            Internal.SHA256.hash initialState bytes
    in
    Digest r.h0 r.h1 r.h2 r.h3 r.h4 r.h5 r.h6


{-| Create a digest from a list of byte values (0-255).

    import SHA224

    SHA224.fromByteValues [ 72, 105, 33, 32, 240, 159, 152, 132 ]
        == SHA224.fromString "Hi! \u{1F604}"
    --> True

-}
fromByteValues : List Int -> Digest
fromByteValues values =
    fromBytes (Encode.encode (Encode.sequence (List.map Encode.unsignedInt8 values)))


{-| Turn a digest into a hex string.

    import SHA224

    SHA224.fromString "And our friends are all aboard"
        |> SHA224.toHex
    --> "43baf0c15656c9c0ecce1e4ccb8491e6e5fe01c50e33d73338e899cb"

-}
toHex : Digest -> String
toHex (Digest h0 h1 h2 h3 h4 h5 h6) =
    wordToHex h0 ++ wordToHex h1 ++ wordToHex h2 ++ wordToHex h3 ++ wordToHex h4 ++ wordToHex h5 ++ wordToHex h6


{-| Turn a digest into a base64 encoded string.

    import SHA224

    SHA224.fromString "Many more of them live next door"
        |> SHA224.toBase64
    --> "jGqILHEjFHl4RGN0oaRtFhktytsyncZyOHob4g=="

-}
toBase64 : Digest -> String
toBase64 digest =
    Internal.Base64.encode (toBytes digest)


{-| Turn a digest into `Bytes`. The width is 28 bytes or 224 bits.
-}
toBytes : Digest -> Bytes
toBytes (Digest h0 h1 h2 h3 h4 h5 h6) =
    Encode.encode
        (Encode.sequence
            [ Encode.unsignedInt32 BE h0
            , Encode.unsignedInt32 BE h1
            , Encode.unsignedInt32 BE h2
            , Encode.unsignedInt32 BE h3
            , Encode.unsignedInt32 BE h4
            , Encode.unsignedInt32 BE h5
            , Encode.unsignedInt32 BE h6
            ]
        )


{-| Turn a digest into a list of byte values (0-255).

    import SHA224

    SHA224.fromString "And the band begins to play"
        |> SHA224.toByteValues
    --> [ 0xac, 0x41, 0xa7, 0x63, 0x89, 0xc4, 0xe1, 0x5a
    --> , 0x7e, 0x3b, 0x9d, 0x4a, 0x24, 0x20, 0xef, 0xd0
    --> , 0x32, 0x78, 0xd8, 0xfc, 0xcb, 0x23, 0x39, 0xa1
    --> , 0xe6, 0xaf, 0xcd, 0x18
    --> ]

-}
toByteValues : Digest -> List Int
toByteValues (Digest h0 h1 h2 h3 h4 h5 h6) =
    wordToBytes h0 ++ wordToBytes h1 ++ wordToBytes h2 ++ wordToBytes h3 ++ wordToBytes h4 ++ wordToBytes h5 ++ wordToBytes h6



-- Helpers


wordToHex : Int -> String
wordToHex w =
    String.fromList
        [ nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 28 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 24 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 20 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 16 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 12 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 8 w))
        , nibbleToChar (Bitwise.and 0x0F (Bitwise.shiftRightZfBy 4 w))
        , nibbleToChar (Bitwise.and 0x0F w)
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


wordToBytes : Int -> List Int
wordToBytes w =
    [ Bitwise.and 0xFF (Bitwise.shiftRightZfBy 24 w)
    , Bitwise.and 0xFF (Bitwise.shiftRightZfBy 16 w)
    , Bitwise.and 0xFF (Bitwise.shiftRightZfBy 8 w)
    , Bitwise.and 0xFF w
    ]
