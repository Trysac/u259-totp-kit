# Project record

## Objective

Provide HOTP and TOTP per RFC 4226 and RFC 6238 with replay-safe verification windows, otpauth provisioning URIs and single-use recovery codes stored as salted scrypt entries.

## Scope

- In scope: `hotp`, `totp`, `verify_totp`, `provisioning_uri`, `generate_recovery_codes`, `RecoveryCodeSet`, and the typed `TotpError` error contract.
- In scope: strict validation of secrets, digits, algorithms, counters, periods and windows; replay detection through the returned time step and the `last_step` argument; provisioning URIs; recovery-code generation, serialization, consumption and remaining count.
- In scope: the standard library only, with a `py.typed` marker for typing.
- Out of scope: QR rendering, secret encryption at rest, rate limiting, and Steam or other non-RFC variants.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Values are filled by the factory; unmeasured entries remain "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 2393106 / 111453 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.1365 |

## Factory run u259 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | deepseek-v4-pro | yes | 1890 | 21990 | 0 | 3328 | 0.0449 |
| 2026-11-10 | fix-1 | deepseek-flash | no | 11741 | 2551 | 0 | 88192 | 0.0036 |
| 2026-11-10 | fix-2 | deepseek-flash | no | 9205 | 3338 | 0 | 80640 | 0.0036 |
| 2026-11-10 | audit | deepseek-flash | no | 32051 | 20360 | 0 | 480512 | 0.0185 |
| 2026-11-10 | fix-3 | deepseek-flash | no | 8655 | 2984 | 0 | 54528 | 0.0033 |
| 2026-11-10 | threat-model | deepseek-flash | no | 33669 | 23085 | 0 | 532096 | 0.0205 |
| 2026-11-10 | fix-4 | deepseek-flash | no | 27609 | 29427 | 0 | 942080 | 0.0246 |
| 2026-11-10 | docs | deepseek-flash | no | 86654 | 7718 | 0 | 256 | 0.0176 |

Total: $0.1365. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
