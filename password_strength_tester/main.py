"""Password Strength API v2 — Flask application.

Endpoints
---------
GET  /health            Health / liveness check.
POST /check_strength    Analyse a single password (enhanced).
POST /generate_password Generate a cryptographically secure password.
POST /check_breach      Check password against HaveIBeenPwned breaches.
POST /bulk_check        Analyse up to 20 passwords in one request.

Improvements over v1
--------------------
  v1                              v2
  ─────────────────────────────── ──────────────────────────────────────
  1 endpoint                      5 endpoints
  score + strength + feedback     + entropy, crack times, char analysis,
                                    policy compliance
  No input validation             Length cap, type checks, JSON guard
  No rate limiting                Per-endpoint rate limits (flask-limiter)
  Debug mode always on            Controlled via FLASK_DEBUG env var
  No error handlers               400 / 404 / 405 / 429 / 500 handlers
  No logging                      Structured request logging
  No password generator           POST /generate_password
  No breach check                 POST /check_breach  (HIBP k-anonymity)
  No bulk analysis                POST /bulk_check    (up to 20 passwords)
"""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from zxcvbn import zxcvbn

from .utils import (
    MAX_BULK_SIZE,
    MAX_PASSWORD_LENGTH,
    analyse_characters,
    check_hibp,
    check_policy,
    generate_password,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False   # preserve insertion order in responses

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["500 per day", "100 per hour"],
    # Limits are disabled when app.config['RATELIMIT_ENABLED'] = False
    # (set automatically in tests via app.testing = True and the config below).
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_VERSION = "2.0.0"

# zxcvbn enforces a hard 72-character limit and raises ValueError above it.
# We truncate the input before calling it; character_analysis and policy
# still operate on the full password.
_ZXCVBN_MAX_LEN = 72

_STRENGTH_LABELS: dict[int, str] = {
    0: "Very Weak",
    1: "Weak",
    2: "Medium",
    3: "Strong",
    4: "Very Strong",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _validate_password(data: dict | None) -> tuple[str | None, str | None]:
    """Validates the ``password`` field from a parsed JSON body.

    Returns:
        ``(password_str, None)`` on success.
        ``(None, error_message)`` on failure.
    """
    if not data:
        return None, "Request body must be valid JSON."
    password = data.get("password")
    if password is None:
        return None, "Field 'password' is required."
    if not isinstance(password, str):
        return None, "Field 'password' must be a string."
    if len(password) == 0:
        return None, "Password must not be empty."
    if len(password) > MAX_PASSWORD_LENGTH:
        return None, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters."
    return password, None


def _full_analysis(password: str) -> dict:
    """Runs zxcvbn plus all custom analysis on *password*.

    zxcvbn is fed at most _ZXCVBN_MAX_LEN characters to avoid quadratic
    slowdowns on very long inputs; character_analysis and policy still
    operate on the full password.

    Returns a dict suitable for use as a JSON response body (or embedded
    inside a bulk response).
    """
    result  = zxcvbn(password[:_ZXCVBN_MAX_LEN])
    score   = result["score"]
    cdt     = result.get("crack_times_display", {})
    feedback = result.get("feedback", {})

    return {
        "score":    score,
        "strength": _STRENGTH_LABELS.get(score, "Unknown"),
        "warning":  feedback.get("warning", ""),
        "feedback": feedback.get("suggestions", []),
        "crack_time_estimates": {
            "online_throttled_100_per_hour":    cdt.get("online_throttling_100_per_hour",          "N/A"),
            "online_no_throttle_10_per_second": cdt.get("online_no_throttling_10_per_second",      "N/A"),
            "offline_slow_1e4_per_second":      cdt.get("offline_slow_hashing_1e4_per_second",     "N/A"),
            "offline_fast_1e10_per_second":     cdt.get("offline_fast_hashing_1e10_per_second",    "N/A"),
        },
        "character_analysis": analyse_characters(password),
        "policy":             check_policy(password),
    }


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def _err_400(exc):
    return jsonify({"error": "Bad request.", "detail": str(exc)}), 400


@app.errorhandler(404)
def _err_404(_exc):
    return jsonify({"error": "Endpoint not found."}), 404


@app.errorhandler(405)
def _err_405(_exc):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(429)
def _err_429(_exc):
    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429


@app.errorhandler(500)
def _err_500(_exc):
    return jsonify({"error": "Internal server error."}), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Liveness / health check.

    Returns ``{"status": "ok", "version": "<api_version>"}``.
    """
    return jsonify({"status": "ok", "version": _API_VERSION}), 200


@app.route("/check_strength", methods=["POST"])
@limiter.limit("30 per minute")
def check_strength():
    """Analyse a single password's strength.

    Request body (JSON):
        password  (str, required)  The password to evaluate.

    Response body (JSON):
        score                   int (0–4) — zxcvbn score.
        strength                str — "Very Weak" … "Very Strong".
        warning                 str — zxcvbn warning (empty if none).
        feedback                list[str] — improvement suggestions.
        crack_time_estimates    dict — time-to-crack under four threat models.
        character_analysis      dict — composition breakdown and entropy values.
        policy                  dict — rule-by-rule compliance results.

    Example::

        POST /check_strength
        {"password": "hunter2"}

        {
          "score": 0, "strength": "Very Weak",
          "warning": "This is a top-10 common password.",
          "feedback": ["Add a word or two. ..."],
          "crack_time_estimates": {...},
          "character_analysis": {"length": 7, ...},
          "policy": {"min_length_8": false, "compliant": false, ...}
        }
    """
    password, err = _validate_password(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    analysis = _full_analysis(password)
    logger.info(
        "check_strength: len=%d score=%d strength=%s",
        len(password), analysis["score"], analysis["strength"],
    )
    return jsonify(analysis), 200


@app.route("/generate_password", methods=["POST"])
@limiter.limit("20 per minute")
def generate_password_route():
    """Generate a cryptographically secure random password.

    Request body (JSON, all fields optional):
        length             int   (4–256, default 16)
        include_uppercase  bool  (default true)
        include_digits     bool  (default true)
        include_symbols    bool  (default true)
        exclude_ambiguous  bool  (default false) — excludes Il1O0o

    Response body (JSON):
        password            str  — the generated password.
        length              int  — actual length.
        strength            str  — strength label.
        score               int  — zxcvbn score (0–4).
        character_analysis  dict — composition breakdown.
    """
    data = request.get_json(silent=True) or {}

    try:
        length            = int(data.get("length",            16))
        include_uppercase = bool(data.get("include_uppercase", True))
        include_digits    = bool(data.get("include_digits",    True))
        include_symbols   = bool(data.get("include_symbols",   True))
        exclude_ambiguous = bool(data.get("exclude_ambiguous", False))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Invalid parameter: {exc}"}), 400

    try:
        password = generate_password(
            length, include_uppercase, include_digits,
            include_symbols, exclude_ambiguous,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    analysis = _full_analysis(password)
    logger.info(
        "generate_password: len=%d score=%d", len(password), analysis["score"]
    )
    return jsonify({
        "password":           password,
        "length":             len(password),
        "strength":           analysis["strength"],
        "score":              analysis["score"],
        "character_analysis": analysis["character_analysis"],
    }), 200


@app.route("/check_breach", methods=["POST"])
@limiter.limit("10 per minute")
def check_breach():
    """Check whether a password appears in known data breaches.

    Uses the HaveIBeenPwned Pwned Passwords API with k-anonymity:
    only the first 5 hex characters of the SHA-1 hash are transmitted,
    so the full password is **never** sent to any external service.

    Request body (JSON):
        password  (str, required)

    Response body (JSON):
        breached     bool | null  — True if found in breaches.
        count        int | null   — Times seen across all breaches.
        sha1_prefix  str          — The 5-char prefix sent to HIBP.
        warning      str | null   — Warning message if breached.
        error        str | null   — Set if the API call failed.
    """
    password, err = _validate_password(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    result = check_hibp(password)
    status = 503 if result.get("error") else 200
    logger.info("check_breach: breached=%s count=%s", result.get("breached"), result.get("count"))
    return jsonify(result), status


@app.route("/bulk_check", methods=["POST"])
@limiter.limit("5 per minute")
def bulk_check():
    """Analyse up to 20 passwords in a single request.

    Request body (JSON):
        passwords  list[str]  (required, 1–20 items)

    Response body (JSON):
        count    int   — Number of passwords submitted.
        results  list  — One entry per password, each containing:
                           index   int   — Zero-based index in input list.
                           ... (same fields as /check_strength) ...
                         or ``{"index": N, "error": "..."}`` if invalid.
    """
    data = request.get_json(silent=True)
    if not data or "passwords" not in data:
        return jsonify({"error": "Field 'passwords' (list) is required."}), 400

    passwords = data["passwords"]
    if not isinstance(passwords, list):
        return jsonify({"error": "Field 'passwords' must be a list."}), 400
    if len(passwords) == 0:
        return jsonify({"error": "Passwords list must not be empty."}), 400
    if len(passwords) > MAX_BULK_SIZE:
        return jsonify({
            "error": f"Maximum {MAX_BULK_SIZE} passwords per request."
        }), 400

    results: list[dict] = []
    for idx, pw in enumerate(passwords):
        if not isinstance(pw, str) or not pw:
            results.append({"index": idx, "error": "Must be a non-empty string."})
            continue
        if len(pw) > MAX_PASSWORD_LENGTH:
            results.append({
                "index": idx,
                "error": f"Exceeds {MAX_PASSWORD_LENGTH} character limit.",
            })
            continue
        results.append({"index": idx, **_full_analysis(pw)})

    logger.info("bulk_check: count=%d", len(passwords))
    return jsonify({"count": len(passwords), "results": results}), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
