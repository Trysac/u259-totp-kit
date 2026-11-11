# Use integer-to-base32 for recovery codes

Status: accepted (generated, pending human review)

## Context

The specification requires recovery codes generated from 5 random bytes, encoded as lowercase base32 (8 characters), formatted `xxxx-xxxx`. The acceptance test expects `bytes([1]*5)` to yield `aeaq-caib`. Standard `base64.b32encode` (bitstream encoding) would produce `aeaeaeae`, failing the test.

## Decision

We interpret the 5 bytes as a big-endian integer and convert to base32 using the standard alphabet, left-padding with 'A' to 8 characters. This matches the provided examples and still provides 40 bits of entropy per code.

## Consequences

The implementation is slightly different from a direct `base64.b32encode` of the raw bytes, but it satisfies the test vectors and is arguably more human-friendly. Storage of normalized codes is covered separately by ADR 0003.
