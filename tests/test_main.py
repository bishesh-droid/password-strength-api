"""Tests for Password Strength API v2.

Covers:
  GET  /health            — liveness check
  POST /check_strength    — single password analysis, all response fields,
                            input validation, edge cases
  POST /generate_password — parameter combinations, output validation
  POST /check_breach      — HIBP mock (breached / clean / error)
  POST /bulk_check        — batch validation, mixed input, limits
  Error handlers          — 404, 405
  Utils unit tests        — entropy, char analysis, policy, password gen
"""

import json
import math
import string
import unittest
from unittest.mock import MagicMock, patch

from password_strength_tester.main import app, limiter
from password_strength_tester.utils import (
    analyse_characters,
    calculate_shannon_entropy,
    check_policy,
    estimate_charset_entropy,
    generate_password,
)


# ---------------------------------------------------------------------------
# Test base: disable rate limiting for all tests
# ---------------------------------------------------------------------------

class _Base(unittest.TestCase):
    def setUp(self):
        # Flask-Limiter 4.x exposes a public `enabled` attribute checked at
        # request time via __check_all_limits_exempt. Setting it False here
        # disables all rate limit enforcement for the duration of each test.
        limiter.enabled = False
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        limiter.enabled = True

    def _post(self, url: str, body: dict) -> tuple:
        resp = self.client.post(
            url,
            data=json.dumps(body),
            content_type="application/json",
        )
        return resp, json.loads(resp.data)

    def _get(self, url: str) -> tuple:
        resp = self.client.get(url)
        return resp, json.loads(resp.data)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

class TestHealth(_Base):

    def test_returns_200(self):
        resp, data = self._get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_response_fields(self):
        _, data = self._get("/health")
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)

    def test_version_is_string(self):
        _, data = self._get("/health")
        self.assertIsInstance(data["version"], str)


# ---------------------------------------------------------------------------
# /check_strength  — input validation
# ---------------------------------------------------------------------------

class TestCheckStrengthValidation(_Base):

    def test_no_body_returns_400(self):
        resp = self.client.post("/check_strength")
        self.assertEqual(resp.status_code, 400)

    def test_empty_json_returns_400(self):
        resp, data = self._post("/check_strength", {})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", data)

    def test_null_password_returns_400(self):
        resp, data = self._post("/check_strength", {"password": None})
        self.assertEqual(resp.status_code, 400)

    def test_non_string_password_returns_400(self):
        resp, _ = self._post("/check_strength", {"password": 12345})
        self.assertEqual(resp.status_code, 400)

    def test_empty_string_returns_400(self):
        resp, _ = self._post("/check_strength", {"password": ""})
        self.assertEqual(resp.status_code, 400)

    def test_password_exceeding_max_length_returns_400(self):
        resp, _ = self._post("/check_strength", {"password": "a" * 1001})
        self.assertEqual(resp.status_code, 400)

    def test_password_at_max_length_returns_200(self):
        resp, _ = self._post("/check_strength", {"password": "a" * 1000})
        self.assertEqual(resp.status_code, 200)

    def test_wrong_content_type_returns_400(self):
        resp = self.client.post(
            "/check_strength",
            data="password=test",
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# /check_strength  — response shape
# ---------------------------------------------------------------------------

class TestCheckStrengthResponseShape(_Base):

    def _analyse(self, password: str) -> dict:
        _, data = self._post("/check_strength", {"password": password})
        return data

    def test_top_level_fields_present(self):
        data = self._analyse("SomePassword123!")
        for field in ("score", "strength", "warning", "feedback",
                      "crack_time_estimates", "character_analysis", "policy"):
            self.assertIn(field, data, msg=f"Missing: {field}")

    def test_score_is_0_to_4(self):
        for pw in ("a", "password", "P@ssw0rd!", "correct-horse-battery-staple-44!"):
            score = self._analyse(pw)["score"]
            self.assertIn(score, range(5), msg=f"score={score} for '{pw}'")

    def test_strength_label_matches_score(self):
        labels = {0: "Very Weak", 1: "Weak", 2: "Medium",
                  3: "Strong",   4: "Very Strong"}
        data = self._analyse("SomePassword123!")
        self.assertEqual(data["strength"], labels[data["score"]])

    def test_feedback_is_list(self):
        data = self._analyse("password")
        self.assertIsInstance(data["feedback"], list)

    def test_warning_is_string(self):
        data = self._analyse("password")
        self.assertIsInstance(data["warning"], str)

    def test_crack_time_fields(self):
        data = self._analyse("correcthorse")
        ct = data["crack_time_estimates"]
        for key in ("online_throttled_100_per_hour",
                    "online_no_throttle_10_per_second",
                    "offline_slow_1e4_per_second",
                    "offline_fast_1e10_per_second"):
            self.assertIn(key, ct, msg=f"Missing crack_time key: {key}")

    def test_character_analysis_fields(self):
        data = self._analyse("TestPass1!")
        ca = data["character_analysis"]
        for field in ("length", "uppercase_count", "lowercase_count",
                      "digit_count", "symbol_count", "unique_chars",
                      "has_repeating_chars", "has_sequential_chars",
                      "shannon_entropy_bits", "estimated_entropy_bits"):
            self.assertIn(field, ca, msg=f"Missing char_analysis key: {field}")

    def test_character_analysis_counts_match(self):
        pw   = "Hello123!"
        data = self._analyse(pw)
        ca   = data["character_analysis"]
        self.assertEqual(ca["length"],          len(pw))
        self.assertEqual(ca["uppercase_count"], sum(1 for c in pw if c.isupper()))
        self.assertEqual(ca["lowercase_count"], sum(1 for c in pw if c.islower()))
        self.assertEqual(ca["digit_count"],     sum(1 for c in pw if c.isdigit()))
        self.assertEqual(ca["symbol_count"],    sum(1 for c in pw if not c.isalnum()))
        self.assertEqual(ca["unique_chars"],    len(set(pw)))

    def test_policy_fields(self):
        data = self._analyse("TestPass1!")
        p = data["policy"]
        for field in ("min_length_8", "min_length_12", "has_uppercase",
                      "has_lowercase", "has_digit", "has_symbol",
                      "no_spaces", "no_repeating_runs",
                      "passed_count", "total_rules", "compliant"):
            self.assertIn(field, p, msg=f"Missing policy key: {field}")

    def test_policy_compliant_for_strong_password(self):
        data = self._analyse("Tr0ub4dor&3-CorrectHorse!")
        self.assertTrue(data["policy"]["compliant"])

    def test_policy_not_compliant_for_short_simple(self):
        data = self._analyse("abc")
        self.assertFalse(data["policy"]["compliant"])


# ---------------------------------------------------------------------------
# /check_strength  — strength levels
# ---------------------------------------------------------------------------

class TestCheckStrengthLevels(_Base):

    def _strength(self, pw: str) -> str:
        _, data = self._post("/check_strength", {"password": pw})
        return data["strength"]

    def test_very_weak(self):
        self.assertEqual(self._strength("password"), "Very Weak")

    def test_weak(self):
        # Score 1 passwords
        s = self._strength("abc123def")
        self.assertIn(s, ("Very Weak", "Weak"))

    def test_strong_or_very_strong(self):
        s = self._strength("Tr0ub4dor&3-CorrectHorse!Staple")
        self.assertIn(s, ("Strong", "Very Strong"))


# ---------------------------------------------------------------------------
# /generate_password
# ---------------------------------------------------------------------------

class TestGeneratePassword(_Base):

    def _gen(self, body: dict = None) -> dict:
        _, data = self._post("/generate_password", body or {})
        return data

    def test_default_returns_200(self):
        resp, _ = self._post("/generate_password", {})
        self.assertEqual(resp.status_code, 200)

    def test_response_fields_present(self):
        data = self._gen()
        for field in ("password", "length", "strength", "score", "character_analysis"):
            self.assertIn(field, data, msg=f"Missing: {field}")

    def test_default_length_is_16(self):
        data = self._gen()
        self.assertEqual(data["length"], 16)
        self.assertEqual(len(data["password"]), 16)

    def test_custom_length(self):
        data = self._gen({"length": 32})
        self.assertEqual(data["length"], 32)

    def test_minimum_length(self):
        data = self._gen({"length": 4})
        self.assertEqual(data["length"], 4)

    def test_maximum_length(self):
        data = self._gen({"length": 256})
        self.assertEqual(data["length"], 256)

    def test_length_too_short_returns_400(self):
        resp, data = self._post("/generate_password", {"length": 3})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", data)

    def test_length_too_long_returns_400(self):
        resp, data = self._post("/generate_password", {"length": 257})
        self.assertEqual(resp.status_code, 400)

    def test_no_symbols(self):
        data = self._gen({"include_symbols": False, "length": 20})
        pw = data["password"]
        self.assertTrue(all(c.isalnum() for c in pw), f"Unexpected symbol in: {pw}")

    def test_no_uppercase(self):
        data = self._gen({"include_uppercase": False, "include_symbols": False,
                          "include_digits": False, "length": 20})
        pw = data["password"]
        self.assertTrue(all(c.islower() for c in pw), f"Unexpected char in: {pw}")

    def test_no_digits(self):
        # Generate many times to reduce flakiness
        for _ in range(5):
            data = self._gen({"include_digits": False, "length": 20})
            pw = data["password"]
            self.assertTrue(
                all(not c.isdigit() for c in pw),
                f"Unexpected digit in: {pw}"
            )

    def test_exclude_ambiguous(self):
        ambiguous = set("Il1O0o")
        for _ in range(10):
            data = self._gen({"exclude_ambiguous": True, "length": 40})
            pw = data["password"]
            self.assertTrue(
                all(c not in ambiguous for c in pw),
                f"Ambiguous char found in: {pw}",
            )

    def test_password_is_string(self):
        data = self._gen()
        self.assertIsInstance(data["password"], str)

    def test_score_is_int(self):
        data = self._gen({"length": 24})
        self.assertIsInstance(data["score"], int)

    def test_two_calls_produce_different_passwords(self):
        p1 = self._gen({"length": 32})["password"]
        p2 = self._gen({"length": 32})["password"]
        self.assertNotEqual(p1, p2)

    def test_invalid_length_type_returns_400(self):
        resp, _ = self._post("/generate_password", {"length": "not-a-number"})
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# /check_breach  (HIBP mocked)
# ---------------------------------------------------------------------------

class TestCheckBreach(_Base):

    _MOCK_TARGET = "password_strength_tester.utils.requests.get"

    def _mock_hibp(self, response_text: str, status_code: int = 200):
        """Returns a mock for requests.get that yields *response_text*."""
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.text = response_text
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_missing_password_returns_400(self):
        resp, _ = self._post("/check_breach", {})
        self.assertEqual(resp.status_code, 400)

    def test_breached_password(self):
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        # prefix = "5BAA6", suffix (35 chars) = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        fake_body = f"AAABBBCCCDDDEEEFFF00011122233344455:5\r\n{suffix}:3861493\r\nZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:1\r\n"

        with patch(self._MOCK_TARGET, return_value=self._mock_hibp(fake_body)):
            resp, data = self._post("/check_breach", {"password": "password"})

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(data["breached"])
        self.assertEqual(data["count"], 3_861_493)
        self.assertIsNotNone(data["warning"])
        self.assertIsNone(data["error"])

    def test_clean_password(self):
        fake_body = "AAABBBCCCDDD:5\r\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:2\r\n"
        with patch(self._MOCK_TARGET, return_value=self._mock_hibp(fake_body)):
            resp, data = self._post("/check_breach", {"password": "ThisPasswordIsNotInHIBP!xY7"})

        self.assertEqual(resp.status_code, 200)
        self.assertFalse(data["breached"])
        self.assertEqual(data["count"], 0)
        self.assertIsNone(data["warning"])
        self.assertIsNone(data["error"])

    def test_hibp_timeout_returns_503(self):
        import requests as _req
        with patch(self._MOCK_TARGET, side_effect=_req.Timeout):
            resp, data = self._post("/check_breach", {"password": "somepassword"})
        self.assertEqual(resp.status_code, 503)
        self.assertIsNotNone(data.get("error"))

    def test_hibp_connection_error_returns_503(self):
        import requests as _req
        with patch(self._MOCK_TARGET, side_effect=_req.ConnectionError):
            resp, data = self._post("/check_breach", {"password": "somepassword"})
        self.assertEqual(resp.status_code, 503)

    def test_sha1_prefix_in_response(self):
        fake_body = "AAABBBCCCDDD:5\r\n"
        with patch(self._MOCK_TARGET, return_value=self._mock_hibp(fake_body)):
            _, data = self._post("/check_breach", {"password": "testpassword"})
        self.assertIn("sha1_prefix", data)
        self.assertEqual(len(data["sha1_prefix"]), 5)

    def test_response_fields_present(self):
        fake_body = "AAABBBCCCDDD:5\r\n"
        with patch(self._MOCK_TARGET, return_value=self._mock_hibp(fake_body)):
            _, data = self._post("/check_breach", {"password": "testpassword"})
        for field in ("breached", "count", "sha1_prefix", "warning", "error"):
            self.assertIn(field, data, msg=f"Missing: {field}")


# ---------------------------------------------------------------------------
# /bulk_check
# ---------------------------------------------------------------------------

class TestBulkCheck(_Base):

    def test_missing_passwords_field_returns_400(self):
        resp, _ = self._post("/bulk_check", {})
        self.assertEqual(resp.status_code, 400)

    def test_non_list_passwords_returns_400(self):
        resp, _ = self._post("/bulk_check", {"passwords": "notalist"})
        self.assertEqual(resp.status_code, 400)

    def test_empty_list_returns_400(self):
        resp, _ = self._post("/bulk_check", {"passwords": []})
        self.assertEqual(resp.status_code, 400)

    def test_exceeding_max_returns_400(self):
        resp, _ = self._post("/bulk_check", {"passwords": ["p"] * 21})
        self.assertEqual(resp.status_code, 400)

    def test_exactly_max_returns_200(self):
        resp, _ = self._post("/bulk_check", {"passwords": ["pass"] * 20})
        self.assertEqual(resp.status_code, 200)

    def test_valid_bulk_returns_correct_count(self):
        passwords = ["password", "hunter2", "Tr0ub4dor&3!"]
        _, data = self._post("/bulk_check", {"passwords": passwords})
        self.assertEqual(data["count"], len(passwords))
        self.assertEqual(len(data["results"]), len(passwords))

    def test_each_result_has_index(self):
        passwords = ["abc", "def", "ghi"]
        _, data = self._post("/bulk_check", {"passwords": passwords})
        for i, result in enumerate(data["results"]):
            self.assertEqual(result["index"], i)

    def test_each_result_has_score_and_strength(self):
        _, data = self._post("/bulk_check", {"passwords": ["password", "P@ssw0rd123!"]})
        for result in data["results"]:
            self.assertIn("score",    result)
            self.assertIn("strength", result)

    def test_empty_string_in_list_returns_error_entry(self):
        _, data = self._post("/bulk_check", {"passwords": ["", "valid"]})
        results = data["results"]
        self.assertIn("error", results[0])   # empty string → error
        self.assertIn("score", results[1])   # valid password → normal result

    def test_non_string_in_list_returns_error_entry(self):
        _, data = self._post("/bulk_check", {"passwords": [123, "valid"]})
        self.assertIn("error", data["results"][0])

    def test_too_long_password_in_list_returns_error_entry(self):
        _, data = self._post("/bulk_check", {"passwords": ["a" * 1001, "ok"]})
        self.assertIn("error", data["results"][0])
        self.assertIn("score", data["results"][1])

    def test_single_password(self):
        resp, data = self._post("/bulk_check", {"passwords": ["TestPass1!"]})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data["count"], 1)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

class TestErrorHandlers(_Base):

    def test_404_unknown_endpoint(self):
        resp = self.client.get("/nonexistent_endpoint")
        self.assertEqual(resp.status_code, 404)
        data = json.loads(resp.data)
        self.assertIn("error", data)

    def test_405_get_on_post_only_endpoint(self):
        resp = self.client.get("/check_strength")
        self.assertEqual(resp.status_code, 405)
        data = json.loads(resp.data)
        self.assertIn("error", data)

    def test_405_post_on_get_only_endpoint(self):
        resp = self.client.post("/health")
        self.assertEqual(resp.status_code, 405)


# ---------------------------------------------------------------------------
# Utils unit tests
# ---------------------------------------------------------------------------

class TestShannonEntropy(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)

    def test_uniform_distribution_maximises_entropy(self):
        # "abcd" — all unique chars — highest entropy per char
        e1 = calculate_shannon_entropy("abcd")
        # "aaaa" — only one unique char — zero per-char entropy
        e2 = calculate_shannon_entropy("aaaa")
        self.assertGreater(e1, e2)

    def test_single_char_repeated_is_zero(self):
        self.assertEqual(calculate_shannon_entropy("aaaaa"), 0.0)

    def test_returns_float(self):
        self.assertIsInstance(calculate_shannon_entropy("hello"), float)

    def test_longer_password_more_bits(self):
        e_short = calculate_shannon_entropy("abc")
        e_long  = calculate_shannon_entropy("abcdefghij")
        self.assertGreater(e_long, e_short)


class TestCharsetEntropy(unittest.TestCase):

    def test_empty_string(self):
        self.assertEqual(estimate_charset_entropy(""), 0.0)

    def test_lowercase_only(self):
        e = estimate_charset_entropy("abcdef")
        expected = round(math.log2(26) * 6, 2)
        self.assertAlmostEqual(e, expected, places=1)

    def test_all_classes_higher_than_single_class(self):
        e_low   = estimate_charset_entropy("abcdef")
        e_all   = estimate_charset_entropy("aB1!")
        # pool for all classes = 94, pool for lowercase = 26
        self.assertGreater(e_all / 4, e_low / 6)   # per-char entropy


class TestAnalyseCharacters(unittest.TestCase):

    def _ac(self, pw: str) -> dict:
        return analyse_characters(pw)

    def test_empty_string(self):
        ca = self._ac("")
        self.assertEqual(ca["length"], 0)
        self.assertEqual(ca["uppercase_count"], 0)

    def test_counts_correct(self):
        ca = self._ac("Hello123!")
        self.assertEqual(ca["uppercase_count"], 1)
        self.assertEqual(ca["lowercase_count"], 4)
        self.assertEqual(ca["digit_count"],     3)
        self.assertEqual(ca["symbol_count"],    1)
        self.assertEqual(ca["length"],          9)
        self.assertEqual(ca["unique_chars"],    len(set("Hello123!")))

    def test_repeating_chars_detected(self):
        self.assertTrue(self._ac("aaabbb")["has_repeating_chars"])
        self.assertFalse(self._ac("abcabc")["has_repeating_chars"])

    def test_sequential_detected(self):
        self.assertTrue(self._ac("abc123")["has_sequential_chars"])
        self.assertFalse(self._ac("acegik")["has_sequential_chars"])

    def test_entropy_keys_present(self):
        ca = self._ac("TestPw1!")
        self.assertIn("shannon_entropy_bits",   ca)
        self.assertIn("estimated_entropy_bits", ca)

    def test_entropy_non_negative(self):
        ca = self._ac("TestPw1!")
        self.assertGreaterEqual(ca["shannon_entropy_bits"],   0)
        self.assertGreaterEqual(ca["estimated_entropy_bits"], 0)


class TestCheckPolicy(unittest.TestCase):

    def test_compliant_password(self):
        p = check_policy("Tr0ub4dor&3-Correct!")
        self.assertTrue(p["compliant"])
        self.assertTrue(p["min_length_12"])
        self.assertTrue(p["has_uppercase"])
        self.assertTrue(p["has_lowercase"])
        self.assertTrue(p["has_digit"])
        self.assertTrue(p["has_symbol"])

    def test_short_password_not_compliant(self):
        p = check_policy("abc")
        self.assertFalse(p["compliant"])
        self.assertFalse(p["min_length_8"])
        self.assertFalse(p["min_length_12"])

    def test_no_symbol_not_compliant(self):
        p = check_policy("CorrectHorse12Battery")
        self.assertFalse(p["compliant"])

    def test_no_digit_not_compliant(self):
        p = check_policy("CorrectHorse!Battery")
        self.assertFalse(p["compliant"])

    def test_space_detected(self):
        p = check_policy("correct horse battery")
        self.assertFalse(p["no_spaces"])

    def test_repeating_run_detected(self):
        p = check_policy("aaaCorrect1!")
        self.assertFalse(p["no_repeating_runs"])

    def test_passed_count_and_total_present(self):
        p = check_policy("Test")
        self.assertIn("passed_count", p)
        self.assertIn("total_rules",  p)
        self.assertIsInstance(p["passed_count"], int)
        self.assertIsInstance(p["total_rules"],  int)

    def test_passed_count_leq_total(self):
        p = check_policy("SomePass1!")
        self.assertLessEqual(p["passed_count"], p["total_rules"])


class TestGeneratePasswordUtil(unittest.TestCase):

    def test_default_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        for n in (4, 16, 64, 128, 256):
            self.assertEqual(len(generate_password(n)), n)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            generate_password(3)

    def test_too_long_raises(self):
        with self.assertRaises(ValueError):
            generate_password(257)

    def test_includes_uppercase(self):
        found = False
        for _ in range(20):
            pw = generate_password(16, include_uppercase=True)
            if any(c.isupper() for c in pw):
                found = True
                break
        self.assertTrue(found)

    def test_no_uppercase(self):
        for _ in range(10):
            pw = generate_password(20, include_uppercase=False,
                                   include_symbols=False, include_digits=False)
            self.assertTrue(all(c.islower() for c in pw), f"Found non-lowercase in: {pw}")

    def test_no_digits(self):
        for _ in range(10):
            pw = generate_password(20, include_digits=False)
            self.assertTrue(all(not c.isdigit() for c in pw), f"Found digit in: {pw}")

    def test_no_symbols(self):
        for _ in range(10):
            pw = generate_password(20, include_symbols=False)
            self.assertTrue(all(c.isalnum() for c in pw), f"Found symbol in: {pw}")

    def test_exclude_ambiguous(self):
        ambiguous = set("Il1O0o")
        for _ in range(20):
            pw = generate_password(40, exclude_ambiguous=True)
            self.assertTrue(
                all(c not in ambiguous for c in pw),
                f"Found ambiguous char in: {pw}",
            )

    def test_returns_string(self):
        self.assertIsInstance(generate_password(), str)

    def test_uniqueness(self):
        passwords = {generate_password(32) for _ in range(10)}
        self.assertEqual(len(passwords), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
