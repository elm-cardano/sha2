module SHA256 exposing
    ( Digest
    , fromBytes
    , toBytes
    )

{-| [SHA-256] is a [cryptographic hash function] that gives 128 bits of security.

[SHA-256]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromBytes


# To binary data

@docs toBytes

-}

import Bytes exposing (Bytes)


{-| An abstract sha256 digest.
-}
type Digest
    = Digest


{-| Create a digest from [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/).
-}
fromBytes : Bytes -> Digest
fromBytes _ =
    Debug.todo "SHA256.fromBytes"


{-| Turn a digest into `Bytes`. The digest is stored as 8 big-endian 32-bit unsigned integers, so the width is 32 bytes or 256 bits.
-}
toBytes : Digest -> Bytes
toBytes _ =
    Debug.todo "SHA256.toBytes"
