"""HOTP and TOTP two-factor authentication with replay-safe verification.

This module implements:
- HOTP (RFC 4226): HMAC-based one-time passwords.
- TOTP (RFC 6238): time-based one-time passwords.
- A verification function that returns the matched time step and detects
  replay within the allowed window.
- Generation of otpauth provisioning URIs.
- Hashed single-use recovery codes.

Threat model:
- Defended: code replay within the window, timing differences in code
  comparison, recovery code disclosure from serialized storage (each code
  is stored as a per-entry random salt plus a memory-hard scrypt tag, with
  an optional server-side pepper), reuse of a consumed recovery code.
- Not defended: phishing relays in real time, brute force without rate
  limiting (caller's responsibility), secret storage at rest, clock drift
  beyond the window.  The 40-bit recovery-code space still requires
  application-level attempt limits and access controls on backups; a
  pepper held outside the datastore is recommended.

All functions raise :class:`TotpError` with a machine-readable ``code``
for invalid inputs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import math
import secrets
from collections.abc import Callable
from typing import Literal
from urllib.parse import quote

__all__ = [
    "RecoveryCodeSet",
    "TotpError",
    "__version__",
    "generate_recovery_codes",
    "hotp",
    "provisioning_uri",
    "totp",
    "verify_totp",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

Algorithm = Literal["sha1", "sha256", "sha512"]

_VALID_ALGORITHMS = {"sha1", "sha256", "sha512"}
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Recovery-code storage uses a memory-hard KDF so that a leaked serialized
# set cannot be enumerated cheaply, even though a recovery code carries only
# 40 bits of entropy.  Each entry has its own random salt; a caller-supplied
# pepper can be kept outside the datastore for defence in depth.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 16
_RECOVERY_SALT_BYTES = 16


class TotpError(Exception):
    """Base error for totp_kit.

    Attributes:
        code: Machine-readable error code, one of ``"weak_secret"``,
            ``"invalid_digits"``, ``"invalid_algorithm"``,
            ``"invalid_counter"``, ``"invalid_period"``,
            ``"invalid_window"``, ``"input_too_large"``, ``"replayed"``,
            ``"invalid_json"``.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _validate_secret(secret: bytes) -> None:
    if len(secret) < 16 or len(secret) > 128:
        raise TotpError("weak_secret")


def _validate_digits(digits: int) -> None:
    if digits not in (6, 7, 8):
        raise TotpError("invalid_digits")


def _validate_algorithm(algorithm: str) -> None:
    if algorithm not in _VALID_ALGORITHMS:
        raise TotpError("invalid_algorithm")


def _validate_period(period: int) -> None:
    if period < 1 or period > 300:
        raise TotpError("invalid_period")


def _validate_window(window: int) -> None:
    if window < 0 or window > 10:
        raise TotpError("invalid_window")


def hotp(
    secret: bytes,
    counter: int,
    *,
    digits: int = 6,
    algorithm: Algorithm = "sha1",
) -> str:
    """Generate an HMAC-based one-time password per RFC 4226 section 5.3.

    Args:
        secret: Shared secret, 16 to 128 bytes.
        counter: 8-byte counter value, 0 to 2**64-1.
        digits: Number of digits in the OTP (6, 7, or 8).
        algorithm: HMAC hash algorithm.

    Returns:
        The OTP as a zero-padded string of length ``digits``.

    Raises:
        TotpError: If inputs are invalid.
    """
    _validate_secret(secret)
    _validate_digits(digits)
    _validate_algorithm(algorithm)
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise TotpError("invalid_counter")

    counter_bytes = counter.to_bytes(8, "big")
    mac = hmac.new(secret, counter_bytes, getattr(hashlib, algorithm)).digest()
    offset = mac[-1] & 0x0F
    binary = (
        (mac[offset] & 0x7F) << 24
        | (mac[offset + 1] & 0xFF) << 16
        | (mac[offset + 2] & 0xFF) << 8
        | (mac[offset + 3] & 0xFF)
    )
    code = binary % (10**digits)
    return str(code).zfill(digits)


def totp(
    secret: bytes,
    at: float,
    *,
    period: int = 30,
    t0: int = 0,
    digits: int = 6,
    algorithm: Algorithm = "sha1",
) -> str:
    """Generate a time-based one-time password per RFC 6238.

    The time step is ``floor((at - t0) / period)`` which becomes the
    counter for HOTP.

    Args:
        secret: Shared secret, 16 to 128 bytes.
        at: Unix time in seconds.
        period: Time step size in seconds (1 to 300).
        t0: Epoch offset; usually 0.
        digits: Number of digits in the OTP (6, 7, or 8).
        algorithm: HMAC hash algorithm.

    Returns:
        The TOTP as a zero-padded string.

    Raises:
        TotpError: If inputs are invalid or the computed step is outside
            the valid counter range.
    """
    _validate_secret(secret)
    _validate_digits(digits)
    _validate_algorithm(algorithm)
    _validate_period(period)

    step = math.floor((at - t0) / period)
    return hotp(secret, step, digits=digits, algorithm=algorithm)


def verify_totp(
    secret: bytes,
    code: str,
    *,
    at: float,
    window: int = 1,
    last_step: int | None = None,
    period: int = 30,
    digits: int = 6,
    algorithm: Algorithm = "sha1",
) -> int | None:
    """Verify a TOTP code with replay detection.

    The code is stripped of all whitespace and compared against candidates
    generated for steps ``step - window`` through ``step + window`` in
    ascending order. Every candidate is compared using
    :func:`hmac.compare_digest`, even after a match is found, to avoid
    timing leaks. The first matching step is returned.

    If ``last_step`` is provided and the matched step is less than or equal
    to it, :class:`TotpError` with code ``"replayed"`` is raised.

    Args:
        secret: Shared secret, 16 to 128 bytes.
        code: The user-provided code; spaces are ignored.
        at: Unix time in seconds.
        window: Allowed step deviation (0 to 10).
        last_step: Last successfully used step, if any.
        period: Time step size in seconds (1 to 300).
        digits: Number of digits in the OTP (6, 7, or 8).
        algorithm: HMAC hash algorithm.

    Returns:
        The matched time step as an integer, or ``None`` if no match.

    Raises:
        TotpError: If inputs are invalid, the code is too long, or the
            match is a replay.
    """
    _validate_secret(secret)
    _validate_digits(digits)
    _validate_algorithm(algorithm)
    _validate_period(period)
    _validate_window(window)

    if len(code) > 32:
        raise TotpError("input_too_large")

    code_normalized = "".join(code.split())
    if (
        len(code_normalized) != digits
        or not code_normalized.isascii()
        or not code_normalized.isdigit()
    ):
        return None

    step = math.floor((at - 0) / period)
    # verify_totp has no t0 parameter, so the epoch offset is always 0.
    if step < 0 or step > 0xFFFFFFFFFFFFFFFF:
        return None

    start = max(0, step - window)
    end = step + window
    if end > 0xFFFFFFFFFFFFFFFF:
        end = 0xFFFFFFFFFFFFFFFF

    first_match: int | None = None
    for counter in range(start, end + 1):
        candidate = hotp(secret, counter, digits=digits, algorithm=algorithm)
        matches = hmac.compare_digest(code_normalized, candidate)
        if matches and first_match is None:
            first_match = counter

    if first_match is not None:
        if last_step is not None and first_match <= last_step:
            raise TotpError("replayed")
        return first_match
    return None


def provisioning_uri(
    secret: bytes,
    *,
    account: str,
    issuer: str,
    digits: int = 6,
    period: int = 30,
    algorithm: Algorithm = "sha1",
) -> str:
    """Generate an otpauth provisioning URI per the Key Uri Format.

    The label is ``issuer:account`` with both parts percent-encoded.  The
    secret is unpadded RFC 4648 base32.  Query parameters appear in the
    order: secret, issuer, algorithm (uppercase), digits, period.

    Args:
        secret: Shared secret, 16 to 128 bytes.
        account: Account name (e.g., user@example.com).
        issuer: Issuer/provider name.
        digits: Number of digits (6, 7, or 8).
        period: Time step size in seconds (1 to 300).
        algorithm: HMAC hash algorithm.

    Returns:
        The complete ``otpauth://totp/...`` URI.

    Raises:
        TotpError: If inputs are invalid.
    """
    _validate_secret(secret)
    _validate_digits(digits)
    _validate_algorithm(algorithm)
    _validate_period(period)

    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    secret_b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    params = [
        ("secret", secret_b32),
        ("issuer", quote(issuer, safe="")),
        ("algorithm", algorithm.upper()),
        ("digits", str(digits)),
        ("period", str(period)),
    ]
    query = "&".join(f"{key}={value}" for key, value in params)
    return f"otpauth://totp/{label}?{query}"


def _int_to_base32(value: int) -> str:
    """Convert a non-negative integer to base32 (no padding)."""
    if value == 0:
        return "A"
    result = ""
    while value > 0:
        result = _BASE32_ALPHABET[value % 32] + result
        value //= 32
    return result


def generate_recovery_codes(
    count: int = 10,
    *,
    rng: Callable[[int], bytes] = secrets.token_bytes,
) -> list[str]:
    """Generate unique recovery codes.

    Each code is derived from 5 random bytes interpreted as a big-endian
    integer, converted to lowercase base32 (8 characters), and formatted
    as ``xxxx-xxxx``.  Duplicates are redrawn up to 100 times; if a
    duplicate still occurs, a :class:`TotpError` with code
    ``"input_too_large"`` is raised (astronomically unlikely with a proper
    RNG).

    Args:
        count: Number of codes to generate (0 to 100).
        rng: A callable that returns ``n`` random bytes.

    Returns:
        A list of formatted codes.

    Raises:
        TotpError: If ``count`` is out of range, the RNG returns the wrong
            number of bytes, or too many collisions occur.
    """
    if count < 0 or count > 100:
        raise TotpError("input_too_large")

    codes: list[str] = []
    seen: set[str] = set()
    for _ in range(count):
        for _ in range(100):
            raw = rng(5)
            if len(raw) != 5:
                raise TotpError("input_too_large")
            value = int.from_bytes(raw, "big")
            code_str = _int_to_base32(value).rjust(8, "A").lower()
            code = f"{code_str[:4]}-{code_str[4:]}"
            if code not in seen:
                seen.add(code)
                codes.append(code)
                break
        else:
            raise TotpError("input_too_large")
    return codes


def _normalize_recovery_code(code: str) -> str | None:
    """Normalize a recovery code to lowercase ``xxxx-xxxx``.

    Returns ``None`` if the code does not normalize to exactly eight
    characters, so callers can decide whether a malformed code is a
    developer error (``from_codes``) or simply an invalid user input
    (``consume``).
    """
    cleaned = "".join(code.split()).replace("-", "").lower()
    if len(cleaned) != 8:
        return None
    return f"{cleaned[:4]}-{cleaned[4:]}"


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _recovery_password(normalized: str, pepper: bytes | None) -> bytes:
    """Return the KDF input for a normalized code.

    A caller-supplied pepper is mixed in with HMAC so that the pepper lives
    outside the datastore and a leaked JSON set is useless without it.
    """
    password = normalized.encode("utf-8")
    if pepper is not None:
        password = hmac.new(pepper, password, hashlib.sha256).digest()
    return password


def _derive_recovery_entry(normalized: str, salt: bytes, pepper: bytes | None) -> str:
    """Derive one self-contained ``salt || scrypt`` storage entry.

    The salt is 16 bytes and the scrypt tag is 16 bytes, so the result is
    exactly 64 hex characters: the same shape the JSON format has always
    used.  The memory-hard KDF makes offline enumeration of the small
    recovery-code space expensive and the per-entry random salt prevents a
    table from being reused across users or sets.
    """
    tag = hashlib.scrypt(
        _recovery_password(normalized, pepper),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return (salt + tag).hex()


class RecoveryCodeSet:
    """A set of single-use recovery codes stored as salted scrypt entries.

    Plain codes are never serialized.  Each entry is a random 16-byte salt
    followed by a 16-byte scrypt tag, encoded as 64 hex characters, so a
    leaked ``to_json()`` value cannot be enumerated cheaply.  Callers may
    also pass a ``pepper`` (kept outside the datastore) to ``from_codes``
    and ``from_json`` for additional protection.

    The ``_hashes`` attribute is an in-memory compatibility view only; it
    is never written by ``to_json`` and is not used for verification.
    """

    def __init__(
        self,
        hashes: set[str],
        *,
        entries: set[str] | None = None,
        pepper: bytes | None = None,
    ) -> None:
        self._hashes = hashes
        self._entries = set(hashes) if entries is None else entries
        self._pepper = pepper

    @classmethod
    def from_codes(
        cls,
        codes: list[str],
        *,
        pepper: bytes | None = None,
    ) -> RecoveryCodeSet:
        """Create a set from a list of plain recovery codes.

        Codes are normalized (spaces/hyphens removed, lowercase, hyphen
        re-inserted) before derivation.  Each code gets its own random
        salt and a memory-hard scrypt entry.

        Args:
            codes: List of code strings; at most 100 codes.
            pepper: Optional server-side secret held outside the datastore.

        Returns:
            A new :class:`RecoveryCodeSet`.

        Raises:
            TotpError: If more than 100 codes are provided or a code is
                malformed.
        """
        if len(codes) > 100:
            raise TotpError("input_too_large")
        hashes: set[str] = set()
        entries: set[str] = set()
        for code in codes:
            normalized = _normalize_recovery_code(code)
            if normalized is None:
                raise TotpError("input_too_large")
            # Kept for the historical in-memory view; never serialized.
            hashes.add(hashlib.sha256(normalized.encode("utf-8")).hexdigest())
            salt = secrets.token_bytes(_RECOVERY_SALT_BYTES)
            entries.add(_derive_recovery_entry(normalized, salt, pepper))
        return cls(hashes, entries=entries, pepper=pepper)

    @classmethod
    def from_json(
        cls,
        text: str,
        *,
        pepper: bytes | None = None,
    ) -> RecoveryCodeSet:
        """Deserialize a :class:`RecoveryCodeSet` from JSON.

        The JSON must be a list of 64-character hex strings (salt plus
        scrypt tag entries).  Input size is limited to 64 KiB and at most
        100 entries.

        Args:
            text: JSON string.
            pepper: The same server-side secret used to create the set.

        Returns:
            A new :class:`RecoveryCodeSet`.

        Raises:
            TotpError: With code ``"input_too_large"`` if the input is too
                large or has too many codes, or ``"invalid_json"`` if the
                JSON is malformed.
        """
        if len(text.encode("utf-8")) > 64 * 1024:
            raise TotpError("input_too_large")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise TotpError("invalid_json") from None
        if not isinstance(data, list):
            raise TotpError("invalid_json")
        if len(data) > 100:
            raise TotpError("input_too_large")
        entries: set[str] = set()
        for item in data:
            if not isinstance(item, str) or len(item) != 64 or not _is_hex(item):
                raise TotpError("invalid_json")
            entries.add(item)
        return cls(set(), entries=entries, pepper=pepper)

    def to_json(self) -> str:
        """Serialize the set to a JSON list of salted scrypt entries."""
        return json.dumps(sorted(self._entries))

    def consume(self, code: str) -> bool:
        """Consume a recovery code.

        The code is normalized, derived with each entry's salt, and
        compared against every stored entry using
        :func:`hmac.compare_digest`.  All entries are compared even after
        a match.  If a match is found, the entry is removed and ``True``
        is returned; otherwise ``False``.  A malformed code (wrong length)
        simply returns ``False`` rather than raising, so attacker-supplied
        input is always safe to pass in from an ``if`` condition.

        Args:
            code: The code supplied by the user.

        Returns:
            ``True`` if the code was valid and has been consumed,
            ``False`` otherwise.
        """
        normalized = _normalize_recovery_code(code)
        if normalized is None:
            return False
        matched: list[str] = []
        for stored in self._entries:
            salt = bytes.fromhex(stored[:32])
            candidate = _derive_recovery_entry(normalized, salt, self._pepper)
            if hmac.compare_digest(candidate, stored):
                matched.append(stored)
        for entry in matched:
            self._entries.discard(entry)
        return bool(matched)

    def remaining(self) -> int:
        """Return the number of unused codes."""
        return len(self._entries)
