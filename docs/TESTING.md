# Testing

## Running

```sh
python -m pytest
```

## Policy

- Tests import the public package (`import totp_kit`) and call the documented functions and classes.
- Tests pass explicit `at` values to TOTP functions rather than reading the wall clock.
- Error cases assert the raised `TotpError.code` value.
- Tests use the RFC 4226 and RFC 6238 published vectors, including leading-zero codes, SHA-1, SHA-256 and SHA-512 variants, and the minimum 16-byte secret.

## Tiers

There is one tier: the local pytest suite in `tests/test_totp_kit.py`. It requires no network access and no external tools.

## Layout

All tests are in `tests/test_totp_kit.py`. The visible classes are `TestHotp` and `TestTotp`; named tests include `test_rfc4226_vectors`, `test_digits_range`, `test_minimum_secret_length`, `test_algorithm_variants`, `test_weak_secret`, `test_invalid_digits`, `test_invalid_algorithm`, `test_invalid_counter`, `test_rfc6238_sha1_vectors`, and `test_rfc6238_sha256_vector`.
