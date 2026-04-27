module Internal.Helper exposing (wordToBytes)

import Bitwise


wordToBytes : Int -> List Int
wordToBytes w =
    [ Bitwise.and 0xFF (Bitwise.shiftRightZfBy 24 w)
    , Bitwise.and 0xFF (Bitwise.shiftRightZfBy 16 w)
    , Bitwise.and 0xFF (Bitwise.shiftRightZfBy 8 w)
    , Bitwise.and 0xFF w
    ]
