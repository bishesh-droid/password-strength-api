"""Utility functions for password analysis and generation.

Provides:
  - Shannon entropy and charset-based entropy estimation
  - Detailed character composition analysis
  - Policy compliance checking
  - Cryptographically secure password generation
  - HaveIBeenPwned k-anonymity breach checking
"""

import hashlib
import math
import re
import secrets
import string

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PASSWORD_LENGTH = 1000   # Hard cap on accepted password length
MAX_BULK_SIZE       = 20     # Maximum passwords per bulk_check request

# Characters that can be visually confused (e.g. I / l / 1, O / 0)
_AMBIGUOUS = set("Il1O0o")


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(password: str) -> float:
    """Computes the Shannon entropy (in bits) of the character distribution.

    Measures how uniformly characters are distributed across the password.
    A higher value means less repetition and a more random-looking string.

    Returns total entropy bits (per-character entropy × length).
    """
    if not password:
        return 0.0
    n = len(password)
    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    per_char = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return round(per_char * n, 2)


def estimate_charset_entropy(password: str) -> float:
    """Estimates entropy using the character pool (log2(pool_size) × length).

    Represents the *theoretical maximum* entropy given which character
    classes are present.  A password using all four classes (lower,
    upper, digits, symbols) has a pool of ~94 characters.

    Calculation:
        pool  = 26 (lower) + 26 (upper) + 10 (digits) + 32 (symbols)
        bits  = log2(pool) × length
    """
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return round(math.log2(pool) * len(password), 2)


# ---------------------------------------------------------------------------
# Character analysis
# ---------------------------------------------------------------------------

def _has_sequential(password: str) -> bool:
    """Returns True if the password contains 3+ consecutive sequential characters.

    Detects ascending (abc, 123) and descending (cba, 321) sequences,
    case-insensitively.
    """
    p = password.lower()
    for i in range(len(p) - 2):
        a, b, c = ord(p[i]), ord(p[i + 1]), ord(p[i + 2])
        if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
            return True
    return False


def analyse_characters(password: str) -> dict:
    """Detailed character composition analysis of a password.

    Returns:
        length                  Total character count.
        uppercase_count         Number of A-Z characters.
        lowercase_count         Number of a-z characters.
        digit_count             Number of 0-9 characters.
        symbol_count            Number of non-alphanumeric characters.
        unique_chars            Number of distinct characters used.
        has_repeating_chars     True if any character repeats 3+ times in a row.
        has_sequential_chars    True if 3+ consecutive sequential chars found.
        shannon_entropy_bits    Shannon entropy (character distribution quality).
        estimated_entropy_bits  Charset-based entropy estimate (theoretical max).
    """
    n = len(password)
    return {
        "length":                  n,
        "uppercase_count":         sum(1 for c in password if c.isupper()),
        "lowercase_count":         sum(1 for c in password if c.islower()),
        "digit_count":             sum(1 for c in password if c.isdigit()),
        "symbol_count":            sum(1 for c in password if not c.isalnum()),
        "unique_chars":            len(set(password)),
        "has_repeating_chars":     bool(re.search(r"(.)\1{2,}", password)),
        "has_sequential_chars":    _has_sequential(password),
        "shannon_entropy_bits":    calculate_shannon_entropy(password),
        "estimated_entropy_bits":  estimate_charset_entropy(password),
    }


# ---------------------------------------------------------------------------
# Policy checker
# ---------------------------------------------------------------------------

def check_policy(password: str) -> dict:
    """Checks a password against a common strong-password policy.

    Rules checked:
        min_length_8            At least 8 characters.
        min_length_12           At least 12 characters (recommended minimum).
        has_uppercase           Contains at least one uppercase letter.
        has_lowercase           Contains at least one lowercase letter.
        has_digit               Contains at least one digit.
        has_symbol              Contains at least one symbol/special character.
        no_spaces               Does not contain whitespace.
        no_repeating_runs       No character repeated 3+ times consecutively.

    A password is ``compliant`` when it satisfies the following subset:
        min_length_12 + has_uppercase + has_lowercase + has_digit + has_symbol.

    Returns:
        A dict with each rule name mapped to a bool, plus:
            passed_count    Number of rules passed.
            total_rules     Total number of rules.
            compliant       Whether the password meets the full policy.
    """
    n = len(password)
    rules = {
        "min_length_8":         n >= 8,
        "min_length_12":        n >= 12,
        "has_uppercase":        any(c.isupper() for c in password),
        "has_lowercase":        any(c.islower() for c in password),
        "has_digit":            any(c.isdigit() for c in password),
        "has_symbol":           any(not c.isalnum() for c in password),
        "no_spaces":            " " not in password,
        "no_repeating_runs":    not bool(re.search(r"(.)\1{2,}", password)),
    }
    compliant = all([
        rules["min_length_12"],
        rules["has_uppercase"],
        rules["has_lowercase"],
        rules["has_digit"],
        rules["has_symbol"],
    ])
    return {
        **rules,
        "passed_count": sum(1 for v in rules.values() if v),
        "total_rules":  len(rules),
        "compliant":    compliant,
    }


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generates a cryptographically secure random password.

    Uses :mod:`secrets` (backed by ``os.urandom``) for all randomness.

    Each enabled character class contributes exactly one *guaranteed*
    character to ensure the password always satisfies inclusion rules.
    The remaining slots are filled from the full combined pool, then the
    result is shuffled so the guaranteed characters are not predictable.

    Args:
        length:            Total character count (4–256).
        include_uppercase: Include A-Z characters.
        include_digits:    Include 0-9 characters.
        include_symbols:   Include punctuation/symbols.
        exclude_ambiguous: Exclude visually confusing characters (Il1O0o).

    Returns:
        A password string of exactly *length* characters.

    Raises:
        ValueError: If *length* is outside 4–256.
    """
    if not (4 <= length <= 256):
        raise ValueError("Password length must be between 4 and 256.")

    def _pool(chars: str) -> list[str]:
        return [c for c in chars if c not in _AMBIGUOUS] if exclude_ambiguous else list(chars)

    lower_pool  = _pool(string.ascii_lowercase)
    upper_pool  = _pool(string.ascii_uppercase)
    digit_pool  = _pool(string.digits)
    symbol_pool = list(string.punctuation)

    if not lower_pool:
        raise ValueError("Character pool is empty after applying exclusions.")

    # Start with one guaranteed lowercase character
    required  = [secrets.choice(lower_pool)]
    char_pool = list(lower_pool)

    if include_uppercase and upper_pool:
        required.append(secrets.choice(upper_pool))
        char_pool.extend(upper_pool)
    if include_digits and digit_pool:
        required.append(secrets.choice(digit_pool))
        char_pool.extend(digit_pool)
    if include_symbols:
        required.append(secrets.choice(symbol_pool))
        char_pool.extend(symbol_pool)

    # Fill remaining length from the combined pool
    fill   = [secrets.choice(char_pool) for _ in range(length - len(required))]
    result = required + fill

    # Shuffle so guaranteed chars don't cluster at the front
    secrets.SystemRandom().shuffle(result)
    return "".join(result)


# ---------------------------------------------------------------------------
# HaveIBeenPwned breach checker
# ---------------------------------------------------------------------------

def check_hibp(password: str) -> dict:
    """Checks whether a password has appeared in known data breaches.

    Uses the HaveIBeenPwned Pwned Passwords API with k-anonymity:
    only the first 5 hex characters of the SHA-1 hash are transmitted,
    so the full password is never sent over the network.

    Args:
        password: The plaintext password to check.

    Returns:
        A dict with:
            breached    bool | None  — True if found, False if not, None on error.
            count       int | None   — Number of breach occurrences (0 if not found).
            sha1_prefix str          — The 5-char prefix that was sent.
            warning     str | None   — Human-readable warning if breached.
            error       str | None   — Error message if the API call failed.
    """
    sha1   = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5,
        )
        resp.raise_for_status()
    except requests.Timeout:
        return {"breached": None, "count": None, "sha1_prefix": prefix,
                "warning": None, "error": "HIBP API timed out."}
    except requests.RequestException as exc:
        return {"breached": None, "count": None, "sha1_prefix": prefix,
                "warning": None, "error": f"HIBP API error: {exc}"}

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            return {
                "breached":    True,
                "count":       count,
                "sha1_prefix": prefix,
                "warning":     (
                    f"This password appeared in {count:,} known data breach(es). "
                    "Do not use it."
                ),
                "error": None,
            }

    return {
        "breached":    False,
        "count":       0,
        "sha1_prefix": prefix,
        "warning":     None,
        "error":       None,
    }
