# SHA-256 Optimization Report

## Baseline

**V1** is the original `folkertdev/elm-sha2` implementation. It uses `Array.get` for
round constants, recursive helpers, and a `DeltaState` wrapper type.

**V2** (`elm-cardano/sha2`) is the rewritten implementation, already ~30% faster
than V1 thanks to:

- Fully unrolled 64 rounds (no loops or recursion)
- Round constants inlined as integer literals (no `Array.get`)
- Flat `Int` let-bindings for all intermediate state (no record/tuple wrapping)
- `HalfBlock` record decoder using `map5` + `map2 Tuple.pair` (F5/F8 fast path)
- Optimized `ch` formula: `z ^ (e & (f ^ g))` (3 ops instead of 4)

## Optimizations applied (V3/V4)

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

## Failed experiment

### Eliminate `t2` intermediate variables -- 3% slower (reverted)

Merged `t2` into `ar` to reduce bindings from 4 to 3 per round. Despite fewer
variables, this made the `ar` expression longer and apparently harder for the JS
engine to optimize. The simpler two-step computation was faster.

## Result

```
  Bench.v1_256   ████████████████████   24262 ns/run   baseline
  Bench.v4_256   ███████████            12812 ns/run   47% faster
```

**V4 is almost 2x faster than the original folkertdev implementation.**
