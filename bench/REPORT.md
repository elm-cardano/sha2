# SHA-2 Optimization Report

## Baseline

**folkertdev** is the original `folkertdev/elm-sha2` implementation. It uses
`Array.get` for round constants, recursive helpers, and a `DeltaState` wrapper
type.

**ours** (`elm-cardano/sha2`) is the rewritten implementation. The starting
point was already ~30% faster than folkertdev thanks to:

- Fully unrolled 64 rounds (no loops or recursion)
- Round constants inlined as integer literals (no `Array.get`)
- Flat `Int` let-bindings for all intermediate state (no record/tuple wrapping)
- `HalfBlock` record decoder using `map5` + `map2 Tuple.pair` (F5/F8 fast path)
- Optimized `ch` formula: `z ^ (e & (f ^ g))` (3 ops instead of 4)

The optimizations below were then applied on top.

## Optimizations applied

### 1. Inline `ch` as raw bitwise expressions -- 13% faster

Replaced all 64 calls to the `ch` function with the equivalent bitwise operations
directly in each round's `t1` binding. This eliminates 64 A3 function dispatches
per block.

```elm
-- Before: function call (A3 dispatch in compiled JS)
t1r0 = h7 + bsig1 h4 + ch h4 h5 h6 + 0x428A2F98 + w0

-- After: inline bitwise ops (no dispatch)
t1r0 = h7 + bsig1 h4 + Bitwise.xor h6 (Bitwise.and h4 (Bitwise.xor h5 h6)) + 0x428A2F98 + w0
```

### 2. Inline `maj` as raw bitwise expressions

Same treatment for the `maj` function in all 64 `t2` bindings. Another 64 A3
dispatches eliminated per block.

```elm
-- Before
t2r0 = bsig0 h0 + maj h0 h1 h2

-- After
t2r0 = bsig0 h0 + Bitwise.xor (Bitwise.xor (Bitwise.and h0 h1) (Bitwise.and h0 h2)) (Bitwise.and h1 h2)
```

Combined with (1), this inlining removes **128 function calls per block**.

### 3. Remove 304 out of 312 `unsigned` calls -- 7% faster

Each `unsigned` call compiles to a function wrapping `x >>> 0`. JS bitwise operators
already truncate to 32 bits, and intermediate sums stay well within the 2^53 safe
integer range. We only truly need `unsigned` on the **8 final hash additions**.

```elm
-- Before: unsigned on every intermediate (304 calls in the let-block)
w16 = ssig1 w14 + w9 + ssig0 w1 + w0 |> unsigned
t1r0 = ... |> unsigned
t2r0 = ... |> unsigned
ar0 = t1r0 + t2r0 |> unsigned
er0 = h3 + t1r0 |> unsigned

-- After: unsigned only on the 8 final additions
w16 = ssig1 w14 + w9 + ssig0 w1 + w0
t1r0 = ...
t2r0 = ...
ar0 = t1r0 + t2r0
er0 = h3 + t1r0
...
{ h0 = h0 + ar63 |> unsigned  -- only here
, ...
}
```

### 4. `map5` + `map4` partial application decoder -- 4% faster

Replaced `map5` + 3x `map2 Tuple.pair` with `map5` + `map4` using partial
application. Eliminates all tuple allocations (6 per full block).

```elm
-- Before: 3 Tuple.pair allocations per half-block
halfBlockDecoder =
    Decode.map5
        (\a b ( c, d ) ( e, f ) ( g, h ) -> HalfBlock a b c d e f g h)
        u32 u32
        (Decode.map2 Tuple.pair u32 u32)
        (Decode.map2 Tuple.pair u32 u32)
        (Decode.map2 Tuple.pair u32 u32)

-- After: zero tuples, 1 F3 closure per half-block
halfBlockDecoder =
    Decode.map4 (\partial f g h -> partial f g h)
        (Decode.map5 (\a b c d e -> \f g h -> HalfBlock a b c d e f g h) u32 u32 u32 u32 u32)
        u32 u32 u32
```

### 5. Factor rounds into `twoRounds` function (F5) -- 9% faster

Replaced 64 fully-unrolled rounds (256 let-bindings) with a `twoRounds` function
called 32 times. The function takes two `(k, w)` pairs and a `RoundState` record,
executing two rounds per call.

```elm
type alias RoundState =
    { a : Int, b : Int, c : Int, d : Int, e : Int, f : Int, g : Int, h : Int }

twoRounds : Int -> Int -> Int -> Int -> RoundState -> RoundState
twoRounds k0 w0 k1 w1 s =
    let
        t1a = s.h + bsig1 s.e + Bitwise.xor s.g (Bitwise.and s.e (Bitwise.xor s.f s.g)) + k0 + w0
        t2a = bsig0 s.a + Bitwise.xor (Bitwise.xor (Bitwise.and s.a s.b) (Bitwise.and s.a s.c)) (Bitwise.and s.b s.c)
        a1 = t1a + t2a
        e1 = s.d + t1a
        t1b = s.g + bsig1 e1 + Bitwise.xor s.f (Bitwise.and e1 (Bitwise.xor s.e s.f)) + k1 + w1
        t2b = bsig0 a1 + Bitwise.xor (Bitwise.xor (Bitwise.and a1 s.a) (Bitwise.and a1 s.b)) (Bitwise.and s.a s.b)
        a2 = t1b + t2b
        e2 = s.c + t1b
    in
    { a = a2, b = a1, c = s.a, d = s.b, e = e2, f = e1, g = s.e, h = s.f }

-- compress calls twoRounds 32 times with inlined round constants
s1 = twoRounds 0x428A2F98 w0 0x71374491 w1 s0
s2 = twoRounds 0xB5C0FBCF w2 0xE9B5DBA5 w3 s1
...
```

This is F5 (within Elm's fast-call path) and the smaller function body JITs better
than V4's giant let-block. Despite 32 record allocations per block, the net effect
is a **9% speedup** and a **55% reduction in source code** (591 lines vs 1310).

## Failed experiment

### Eliminate `t2` intermediate variables -- 3% slower (reverted)

Merged `t2` into `ar` to reduce bindings from 4 to 3 per round. Despite fewer
variables, this made the `ar` expression longer and apparently harder for the JS
engine to optimize. The simpler two-step computation was faster.

## Result

| Hash    | Input size | ours (ns/run) | folkertdev (ns/run) | folkertdev slower by |
| ------- | ---------: | ------------: | ------------------: | -------------------: |
| SHA-256 |   64 bytes |         5,161 |              11,066 |                 114% |
| SHA-256 | 4096 bytes |       140,684 |             302,060 |                 115% |
| SHA-512 |  128 bytes |        13,417 |              54,068 |                 303% |
| SHA-512 | 4096 bytes |       199,476 |             888,757 |                 346% |

**SHA-256 is ~2.1x faster and SHA-512 is ~4x faster than the original
folkertdev implementation.**
