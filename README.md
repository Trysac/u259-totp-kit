# trysac-totp-kit

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

HOTP and TOTP per RFC 4226 and RFC 6238 with replay-safe verification, otpauth provisioning URIs and single-use recovery codes stored as salted scrypt entries.

## Features

- `hotp` implements RFC 4226 section 5.3 with HMAC over an 8-byte big-endian counter and dynamic truncation.
- `totp` implements RFC 6238 with `step = floor((at - t0) / period)` and takes time as an argument, so callers control the clock.
- `verify_totp` returns the matched time step and raises `TotpError("replayed")` when a step at or before `last_step` is reused.
- `provisioning_uri` emits `otpauth://totp/...` URIs with percent-encoded labels and unpadded base32 secrets.
- `RecoveryCodeSet` serializes only per-entry `salt || scrypt` values; a caller-supplied pepper is optional.
- Invalid inputs raise `TotpError` with a machine-readable `code`; the package has no runtime dependencies.

## Installation

```bash
pip install trysac-totp-kit
```

## Usage

```python
from totp_kit import totp, verify_totp, provisioning_uri, RecoveryCodeSet

secret = b"12345678901234567890"
code = totp(secret, at=59)
step = verify_totp(secret, code, at=59, last_step=None)
uri = provisioning_uri(secret, account="alice@example.com", issuer="Example")
rcs = RecoveryCodeSet.from_codes(["aeaq-caib", "aiba-eaqc"])
print(code, step, uri, rcs.consume("AEAQ CAIB"), rcs.remaining())
```

## Public API

- `hotp(secret: bytes, counter: int, *, digits: int = 6, algorithm: Literal["sha1", "sha256", "sha512"] = "sha1") -> str`
- `totp(secret: bytes, at: float, *, period: int = 30, t0: int = 0, digits: int = 6, algorithm: Literal["sha1", "sha256", "sha512"] = "sha1") -> str`
- `verify_totp(secret: bytes, code: str, *, at: float, window: int = 1, last_step: int | None = None, period: int = 30, digits: int = 6, algorithm: Literal["sha1", "sha256", "sha512"] = "sha1") -> int | None`
- `provisioning_uri(secret: bytes, *, account: str, issuer: str, digits: int = 6, period: int = 30, algorithm: Literal["sha1", "sha256", "sha512"] = "sha1") -> str`
- `generate_recovery_codes(count: int = 10, *, rng: Callable[[int], bytes] = secrets.token_bytes) -> list[str]`
- `RecoveryCodeSet.from_codes(codes, *, pepper=None)`, `from_json(text, *, pepper=None)`, `to_json() -> str`, `consume(code: str) -> bool`, `remaining() -> int`
- `TotpError` carries a `code` attribute.

## Limits and errors

- Secrets are 16 to 128 bytes. `digits` is 6, 7 or 8. `period` is 1 to 300. `window` is 0 to 10. HOTP counters are 0 to `2**64 - 1`.
- `verify_totp` strips all whitespace. A normalized code must be exactly `digits` ASCII digits, otherwise it returns `None`. A raw `code` longer than 32 characters raises `TotpError("input_too_large")`.
- `verify_totp` compares steps from `step - window` through `step + window` in ascending order with `hmac.compare_digest`, compares every candidate even after a match, and returns the first matching step, or `None`.
- If `last_step` is not `None` and the matched step is less than or equal to it, `verify_totp` raises `TotpError("replayed")`.
- `generate_recovery_codes` accepts `count` from 0 to 100, draws 5 bytes per code, and formats 8 lowercase base32 characters as `xxxx-xxxx`. Duplicates are redrawn up to 100 times before `TotpError("input_too_large")`.
- `RecoveryCodeSet.from_codes` accepts at most 100 codes and raises `TotpError("input_too_large")` for a code that does not normalize to exactly eight characters. `from_json` raises `TotpError("invalid_json")` for malformed JSON or non-64-character-hex entries, and `TotpError("input_too_large")` for input over 64 KiB or more than 100 entries. `consume` returns `False` for a malformed code and never raises for user input.
- Error codes are `weak_secret`, `invalid_digits`, `invalid_algorithm`, `invalid_counter`, `invalid_period`, `invalid_window`, `input_too_large`, `replayed`, and `invalid_json`.

## Why not pyotp

This library returns the matched time step from verification so the caller can persist it for replay detection, stores recovery codes as salted scrypt entries rather than plain text, and validates secrets, digits, periods, windows and counters before generating codes.

## Security

Read the [threat model](docs/SECURITY.md) before using this library in production.

## Development

Run the test suite with `python -m pytest`; see [docs/TESTING.md](docs/TESTING.md).
