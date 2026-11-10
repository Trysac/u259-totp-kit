# totp-kit

[![PyPI version](https://img.shields.io/pypi/v/trysac-totp-kit)](https://pypi.org/project/trysac-totp-kit/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-totp-kit)](LICENSE)
[![CI](https://github.com/Trysac/u259-totp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u259-totp-kit/actions/workflows/ci.yml)

HOTP and TOTP per RFC 4226 and RFC 6238 with replay-safe verification windows, otpauth provisioning URIs and hashed single-use recovery codes

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-totp-kit
# or
uv add trysac-totp-kit
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import totp_kit

# normalize() trims surrounding whitespace and lower-cases the text.
print(totp_kit.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    totp_kit.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
