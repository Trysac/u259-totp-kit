import base64
import hmac
import json

import pytest

from totp_kit import (
    RecoveryCodeSet,
    TotpError,
    generate_recovery_codes,
    hotp,
    provisioning_uri,
    totp,
    verify_totp,
)

SECRET = b"12345678901234567890"  # 20 bytes, valid (>=16)
SECRET_32 = b"12345678901234567890123456789012"  # 32 bytes
SECRET_64 = b"1234567890" * 6 + b"1234"  # 64 bytes


class TestHotp:
    def test_rfc4226_vectors(self):
        expected = [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ]
        for c, exp in enumerate(expected):
            assert hotp(SECRET, c) == exp

    def test_digits_range(self):
        for digits in (6, 7, 8):
            code = hotp(SECRET, 0, digits=digits)
            assert len(code) == digits
            assert code.isdigit()

    def test_minimum_secret_length(self):
        # Exactly 16 bytes is the smallest accepted secret.
        secret = b"0123456789abcdef"
        code = hotp(secret, 0)
        assert len(code) == 6
        assert code.isdigit()

    def test_algorithm_variants(self):
        # Just ensure no exception and different outputs likely
        codes = [
            hotp(SECRET, 0, algorithm="sha1"),
            hotp(SECRET, 0, algorithm="sha256"),
            hotp(SECRET, 0, algorithm="sha512"),
        ]
        assert len(set(codes)) == 3

    def test_weak_secret(self):
        with pytest.raises(TotpError) as exc:
            hotp(b"short", 0)
        assert exc.value.code == "weak_secret"
        with pytest.raises(TotpError) as exc:
            hotp(b"a" * 129, 0)
        assert exc.value.code == "weak_secret"

    def test_invalid_digits(self):
        with pytest.raises(TotpError) as exc:
            hotp(SECRET, 0, digits=5)
        assert exc.value.code == "invalid_digits"
        with pytest.raises(TotpError) as exc:
            hotp(SECRET, 0, digits=9)
        assert exc.value.code == "invalid_digits"

    def test_invalid_algorithm(self):
        with pytest.raises(TotpError) as exc:
            hotp(SECRET, 0, algorithm="md5")
        assert exc.value.code == "invalid_algorithm"

    def test_invalid_counter(self):
        with pytest.raises(TotpError) as exc:
            hotp(SECRET, -1)
        assert exc.value.code == "invalid_counter"
        with pytest.raises(TotpError) as exc:
            hotp(SECRET, 2**64)
        assert exc.value.code == "invalid_counter"


class TestTotp:
    def test_rfc6238_sha1_vectors(self):
        assert totp(SECRET, 59, digits=8) == "94287082"
        assert totp(SECRET, 1111111109, digits=8) == "07081804"
        assert totp(SECRET, 20000000000, digits=8) == "65353130"

    def test_rfc6238_sha256_vector(self):
        assert totp(SECRET_32, 59, digits=8, algorithm="sha256") == "46119246"

    def test_rfc6238_sha512_vector(self):
        assert totp(SECRET_64, 59, digits=8, algorithm="sha512") == "90693936"

    def test_t0_nonzero(self):
        # at = t0 + 30 -> step 1, should equal hotp counter 1
        code = totp(SECRET, 100, t0=70)
        assert code == hotp(SECRET, 1)

    def test_period_range(self):
        assert totp(SECRET, 0, period=1)  # valid minimum
        assert totp(SECRET, 0, period=300)  # valid maximum
        with pytest.raises(TotpError) as exc:
            totp(SECRET, 0, period=0)
        assert exc.value.code == "invalid_period"
        with pytest.raises(TotpError) as exc:
            totp(SECRET, 0, period=301)
        assert exc.value.code == "invalid_period"

    def test_invalid_secret(self):
        with pytest.raises(TotpError) as exc:
            totp(b"x" * 15, 0)
        assert exc.value.code == "weak_secret"

    def test_negative_time_raises_invalid_counter(self):
        # A negative time yields a negative step, which is an invalid
        # HOTP counter and must surface as "invalid_counter".
        with pytest.raises(TotpError) as exc:
            totp(SECRET, -1)
        assert exc.value.code == "invalid_counter"
        with pytest.raises(TotpError) as exc:
            totp(SECRET, -0.5)
        assert exc.value.code == "invalid_counter"


class TestVerifyTotp:
    def test_basic_match(self):
        # at=59, step=1 (since floor(59/30)=1), code for step 1 is 287082
        assert verify_totp(SECRET, "287082", at=59) == 1

    def test_window_allows_adjacent(self):
        # at=89, step=2; default window=1, so step 1 should match
        assert verify_totp(SECRET, "287082", at=89) == 1

    def test_outside_window_returns_none(self):
        # at=120, step=4; window=1 checks steps 3,4,5; step 1 not in range
        assert verify_totp(SECRET, "287082", at=120) is None

    def test_replay_detection(self):
        with pytest.raises(TotpError) as exc:
            verify_totp(SECRET, "287082", at=59, last_step=1)
        assert exc.value.code == "replayed"

    def test_window_zero_only_current_step(self):
        assert verify_totp(SECRET, "287082", at=59, window=0) == 1
        # Step 2's code is not accepted when window=0 at step 1.
        assert verify_totp(SECRET, "359152", at=59, window=0) is None

    def test_wrong_length_returns_none(self):
        assert verify_totp(SECRET, "28708", at=59) is None

    def test_spaces_ignored(self):
        assert verify_totp(SECRET, " 287082 ", at=59) == 1

    def test_non_digit_returns_none(self):
        assert verify_totp(SECRET, "28a082", at=59) is None

    def test_window_validation(self):
        with pytest.raises(TotpError) as exc:
            verify_totp(SECRET, "287082", at=59, window=-1)
        assert exc.value.code == "invalid_window"
        with pytest.raises(TotpError) as exc:
            verify_totp(SECRET, "287082", at=59, window=11)
        assert exc.value.code == "invalid_window"

    def test_code_too_long(self):
        with pytest.raises(TotpError) as exc:
            verify_totp(SECRET, "1" * 33, at=59)
        assert exc.value.code == "input_too_large"

    def test_negative_step_returns_none(self):
        # at < 0 -> step negative; should return None without raising
        assert verify_totp(SECRET, "000000", at=-1) is None

    def test_all_candidates_compared(self, monkeypatch):
        # Every candidate in the window is compared, even after a match,
        # so an early exit cannot leak timing information.
        calls: list[tuple[str, str]] = []
        real_compare = hmac.compare_digest

        def spy(a: str, b: str) -> bool:
            calls.append((a, b))
            return real_compare(a, b)

        monkeypatch.setattr("totp_kit.hmac.compare_digest", spy)
        # at=59 -> step 1; window=1 checks steps 0, 1, 2 (3 comparisons).
        assert verify_totp(SECRET, "287082", at=59) == 1
        assert len(calls) == 3


class TestProvisioningUri:
    def test_expected_uri(self):
        secret_b32 = base64.b32encode(SECRET).decode("ascii").rstrip("=")
        expected = (
            f"otpauth://totp/Example:alice%40example.com?secret={secret_b32}"
            "&issuer=Example&algorithm=SHA1&digits=6&period=30"
        )
        assert provisioning_uri(SECRET, account="alice@example.com", issuer="Example") == expected

    def test_issuer_and_account_percent_encoded(self):
        uri = provisioning_uri(SECRET, account="a b:c", issuer="Iss:uer")
        assert "Iss%3Auer:a%20b%3Ac" in uri

    def test_algorithm_uppercase(self):
        uri = provisioning_uri(SECRET, account="a", issuer="i", algorithm="sha256")
        assert "algorithm=SHA256" in uri

    def test_parameters_order(self):
        uri = provisioning_uri(SECRET, account="a", issuer="i", digits=7, period=60)
        query = uri.split("?", 1)[1]
        keys = [p.split("=", 1)[0] for p in query.split("&")]
        assert keys == ["secret", "issuer", "algorithm", "digits", "period"]


class TestGenerateRecoveryCodes:
    def test_vectors_from_spec(self):
        class FakeRng:
            def __init__(self, values):
                self._values = iter(values)

            def __call__(self, n):
                assert n == 5
                val = next(self._values)
                return bytes([val] * 5)

        rng = FakeRng([1, 2, 3])
        codes = generate_recovery_codes(3, rng=rng)
        assert codes == ["aeaq-caib", "aiba-eaqc", "ambq-gayd"]

    def test_duplicate_redraw(self):
        # First draw repeats for the second code, so it is redrawn with a
        # fresh value and the generated codes stay unique.
        class FakeRng:
            def __init__(self):
                self.calls = 0

            def __call__(self, n):
                self.calls += 1
                if self.calls <= 2:
                    return b"\x01" * 5
                else:
                    return b"\x02" * 5

        rng = FakeRng()
        codes = generate_recovery_codes(2, rng=rng)
        assert len(codes) == 2
        assert len(set(codes)) == 2
        assert codes[1] != codes[0]

    def test_count_bounds(self):
        assert generate_recovery_codes(0) == []
        assert len(generate_recovery_codes(100)) == 100
        with pytest.raises(TotpError) as exc:
            generate_recovery_codes(-1)
        assert exc.value.code == "input_too_large"
        with pytest.raises(TotpError) as exc:
            generate_recovery_codes(101)
        assert exc.value.code == "input_too_large"


class TestRecoveryCodeSet:
    def test_from_codes_stores_hashes(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"])
        assert rcs._hashes == {"9e56f7295c14f36516e95f200969ad81f6086f6f9f7660a2b66d950292ead0f3"}

    def test_to_json_uses_per_set_salted_scrypt(self):
        first = json.loads(RecoveryCodeSet.from_codes(["aeaq-caib"]).to_json())
        second = json.loads(RecoveryCodeSet.from_codes(["aeaq-caib"]).to_json())
        assert len(first) == 1
        assert len(first[0]) == 64
        # A fast unsalted digest would be identical for both sets.
        assert first != second
        assert first[0] != "9e56f7295c14f36516e95f200969ad81f6086f6f9f7660a2b66d950292ead0f3"

    def test_pepper_is_required_to_consume(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"], pepper=b"server-pepper")
        restored = RecoveryCodeSet.from_json(rcs.to_json(), pepper=b"server-pepper")
        assert restored.consume("AEAQ CAIB") is True
        wrong = RecoveryCodeSet.from_json(rcs.to_json(), pepper=b"other-pepper")
        assert wrong.consume("aeaq-caib") is False

    def test_consume_success_and_reuse(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"])
        assert rcs.consume("AEAQ CAIB") is True
        assert rcs.remaining() == 0
        assert rcs.consume("AEAQ CAIB") is False

    def test_from_codes_rejects_malformed(self):
        with pytest.raises(TotpError) as exc:
            RecoveryCodeSet.from_codes(["short"])
        assert exc.value.code == "input_too_large"

    def test_consume_malformed_returns_false(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"])
        assert rcs.consume("short") is False
        assert rcs.consume("") is False
        assert rcs.remaining() == 1

    def test_to_json_no_plain_code(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"])
        json_str = rcs.to_json()
        assert "aeaq-caib" not in json_str
        parsed = json.loads(json_str)
        assert len(parsed) == 1
        assert len(parsed[0]) == 64

    def test_from_json_valid(self):
        rcs = RecoveryCodeSet.from_codes(["aeaq-caib"])
        json_str = rcs.to_json()
        rcs2 = RecoveryCodeSet.from_json(json_str)
        assert rcs2.remaining() == 1
        assert rcs2.consume("aeaq-caib") is True

    def test_from_json_invalid(self):
        with pytest.raises(TotpError) as exc:
            RecoveryCodeSet.from_json("not json")
        assert exc.value.code == "invalid_json"
        with pytest.raises(TotpError) as exc:
            RecoveryCodeSet.from_json("{}")  # not a list
        assert exc.value.code == "invalid_json"

    def test_from_json_size_limit(self):
        big = "[" + ",".join('"' + "a" * 64 + '"' for _ in range(101)) + "]"
        with pytest.raises(TotpError) as exc:
            RecoveryCodeSet.from_json(big)
        assert exc.value.code == "input_too_large"

    def test_from_json_hex_validation(self):
        with pytest.raises(TotpError) as exc:
            RecoveryCodeSet.from_json('["nothex"]')
        assert exc.value.code == "invalid_json"
