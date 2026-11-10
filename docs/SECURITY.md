# Security

## Threat Model

This library provides cryptographic primitives for two-factor authentication. It defends against the following attacks:

- **Code replay within the verification window**: `verify_totp` returns the matched time step. When `last_step` is provided and the matched step is less than or equal to it, it raises `TotpError("replayed")`. The window is limited to 0 to 10 steps and the period to 1 to 300 seconds.
- **Timing differences in code comparison**: every candidate step from `step - window` through `step + window` is compared with `hmac.compare_digest`, including steps after a match. `verify_totp` returns the first matching step; it does not exit early on mismatch.
- **Recovery code disclosure from storage**: plain codes are never serialized. Each `to_json()` entry is a 16-byte random per-entry salt followed by a 16-byte tag from `hashlib.scrypt(n=2**14, r=8, p=1, dklen=16)`, hex-encoded to 64 characters. A caller may pass a `pepper` to `from_codes` or `from_json`; the pepper is mixed in with HMAC-SHA-256 and is intended to be held outside the datastore. The 40-bit recovery-code space still requires application-level attempt limits and access controls on backups.
- **Reuse of a consumed recovery code**: `RecoveryCodeSet.consume` normalizes the code, compares it against every stored salted scrypt entry with `hmac.compare_digest`, and removes all matching entries after comparison. A consumed code returns `False` on later attempts.

## Not Defended

The caller must implement additional protections:

- **Phishing relays in real time**: an attacker who relays a code immediately can bypass TOTP; consider device attestation or WebAuthn.
- **Brute force without rate limiting**: the library does not throttle verification or recovery-code attempts; implement exponential backoff or account lockout at the application layer.
- **Secret storage at rest**: the library accepts a shared secret as bytes and does not encrypt or store it; provide secure storage such as a KMS or hardware security module.
- **Clock drift beyond the window**: valid codes are rejected when the client and server clocks differ by more than the configured window; synchronize clocks using NTP.

## Reporting a Vulnerability

Please report security issues to the maintainers privately. Do not open a public issue.
