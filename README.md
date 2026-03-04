# Password Strength API v2

A Flask REST API for evaluating password strength, generating secure passwords, and checking passwords against known data-breach databases. Built on [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) with extended analysis, per-endpoint rate limiting, and comprehensive input validation.

---

## What's New in v2

| Feature                     | v1                      | v2                                          |
|-----------------------------|-------------------------|---------------------------------------------|
| Endpoints                   | 1 (`/check_strength`)   | **5 endpoints**                             |
| Password analysis           | score + feedback only   | + entropy, crack times, char analysis, policy |
| Input validation            | None                    | Type checks, length cap, JSON guard         |
| Rate limiting               | None                    | Per-endpoint limits (flask-limiter)         |
| Debug mode                  | Always on               | Controlled via `FLASK_DEBUG` env var        |
| Error handlers              | None                    | 400 / 404 / 405 / 429 / 500                 |
| Logging                     | None                    | Structured request logging                  |
| Password generator          | None                    | `POST /generate_password`                   |
| Breach check                | None                    | `POST /check_breach` (HIBP k-anonymity)     |
| Bulk analysis               | None                    | `POST /bulk_check` (up to 20 passwords)     |

---

## Project Structure

```
password-strength-api/
├── password_strength_tester/
│   ├── __init__.py
│   ├── main.py       # Flask app, all routes, rate limiting, error handlers
│   └── utils.py      # Entropy, char analysis, policy, password gen, HIBP
├── tests/
│   ├── __init__.py
│   └── test_main.py  # 96 tests across all endpoints and utilities
├── api_call_example.txt
├── requirements.txt
└── README.md
```

---

## Prerequisites

- Python 3.10+
- pip

---

## Installation

```bash
git clone https://github.com/your-username/password-strength-api.git
cd password-strength-api

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Running the Server

```bash
python password_strength_tester/main.py
```

The server starts at `http://127.0.0.1:5000`.

To enable debug mode:
```bash
FLASK_DEBUG=true python password_strength_tester/main.py
```

---

## API Reference

### `GET /health`

Liveness check.

```bash
curl http://127.0.0.1:5000/health
```

```json
{"status": "ok", "version": "2.0.0"}
```

---

### `POST /check_strength`

Analyse a single password.

**Rate limit:** 30 requests / minute

**Request:**
```bash
curl -X POST http://127.0.0.1:5000/check_strength \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd!"}'
```

**Response fields:**

| Field                     | Type         | Description                                        |
|---------------------------|--------------|----------------------------------------------------|
| `score`                   | int (0–4)    | zxcvbn strength score                              |
| `strength`                | string       | Label: Very Weak / Weak / Medium / Strong / Very Strong |
| `warning`                 | string       | zxcvbn warning (empty if none)                     |
| `feedback`                | list[string] | Improvement suggestions                            |
| `crack_time_estimates`    | object       | Time-to-crack under four threat models             |
| `character_analysis`      | object       | Composition breakdown and entropy values           |
| `policy`                  | object       | Rule-by-rule compliance results                    |

**`character_analysis` fields:**

| Field                    | Description                                               |
|--------------------------|-----------------------------------------------------------|
| `length`                 | Total character count                                     |
| `uppercase_count`        | Number of A–Z characters                                  |
| `lowercase_count`        | Number of a–z characters                                  |
| `digit_count`            | Number of 0–9 characters                                  |
| `symbol_count`           | Non-alphanumeric characters                               |
| `unique_chars`           | Number of distinct characters                             |
| `has_repeating_chars`    | True if any character repeats 3+ times consecutively      |
| `has_sequential_chars`   | True if 3+ sequential characters found (abc, 123, etc.)   |
| `shannon_entropy_bits`   | Shannon entropy based on character frequency distribution |
| `estimated_entropy_bits` | Theoretical maximum: log₂(pool\_size) × length           |

**`policy` fields:**

| Field               | Description                                              |
|---------------------|----------------------------------------------------------|
| `min_length_8`      | At least 8 characters                                    |
| `min_length_12`     | At least 12 characters (recommended)                     |
| `has_uppercase`     | Contains A–Z                                             |
| `has_lowercase`     | Contains a–z                                             |
| `has_digit`         | Contains 0–9                                             |
| `has_symbol`        | Contains symbols/punctuation                             |
| `no_spaces`         | No whitespace characters                                 |
| `no_repeating_runs` | No character repeated 3+ times consecutively             |
| `passed_count`      | Number of rules passed                                   |
| `total_rules`       | Total rules checked                                      |
| `compliant`         | True when length≥12 + uppercase + lowercase + digit + symbol |

**Example response:**
```json
{
  "score": 3,
  "strength": "Strong",
  "warning": "",
  "feedback": [],
  "crack_time_estimates": {
    "online_throttled_100_per_hour": "centuries",
    "online_no_throttle_10_per_second": "1 year",
    "offline_slow_1e4_per_second": "3 hours",
    "offline_fast_1e10_per_second": "2 minutes"
  },
  "character_analysis": {
    "length": 11,
    "uppercase_count": 1,
    "lowercase_count": 7,
    "digit_count": 1,
    "symbol_count": 2,
    "unique_chars": 10,
    "has_repeating_chars": false,
    "has_sequential_chars": false,
    "shannon_entropy_bits": 34.5,
    "estimated_entropy_bits": 72.1
  },
  "policy": {
    "min_length_8": true,
    "min_length_12": false,
    "has_uppercase": true,
    "has_lowercase": true,
    "has_digit": true,
    "has_symbol": true,
    "no_spaces": true,
    "no_repeating_runs": true,
    "passed_count": 7,
    "total_rules": 8,
    "compliant": false
  }
}
```

---

### `POST /generate_password`

Generate a cryptographically secure random password using `secrets` (backed by `os.urandom`).

**Rate limit:** 20 requests / minute

**Request body (all fields optional):**

| Field               | Type | Default | Description                                      |
|---------------------|------|---------|--------------------------------------------------|
| `length`            | int  | 16      | Character count (4–256)                          |
| `include_uppercase` | bool | true    | Include A–Z                                      |
| `include_digits`    | bool | true    | Include 0–9                                      |
| `include_symbols`   | bool | true    | Include punctuation/symbols                      |
| `exclude_ambiguous` | bool | false   | Exclude visually confusing chars: `Il1O0o`       |

```bash
curl -X POST http://127.0.0.1:5000/generate_password \
  -H "Content-Type: application/json" \
  -d '{"length": 24, "exclude_ambiguous": true}'
```

**Example response:**
```json
{
  "password": "hK#9mP2$nL!8vQ&jCw7RzX3!",
  "length": 24,
  "strength": "Very Strong",
  "score": 4,
  "character_analysis": { "length": 24, "estimated_entropy_bits": 157.3, "..." }
}
```

---

### `POST /check_breach`

Check whether a password appears in known data breaches via the [HaveIBeenPwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords).

Uses **k-anonymity**: only the first 5 hex characters of the SHA-1 hash are transmitted. The full password is **never sent** to any external service.

**Rate limit:** 10 requests / minute

```bash
curl -X POST http://127.0.0.1:5000/check_breach \
  -H "Content-Type: application/json" \
  -d '{"password": "hunter2"}'
```

**Example response (breached):**
```json
{
  "breached": true,
  "count": 17926,
  "sha1_prefix": "4DF90",
  "warning": "This password appeared in 17,926 known data breach(es). Do not use it.",
  "error": null
}
```

**Example response (clean):**
```json
{
  "breached": false,
  "count": 0,
  "sha1_prefix": "A3F91",
  "warning": null,
  "error": null
}
```

**Note:** Returns HTTP 503 if the HIBP API is unreachable.

---

### `POST /bulk_check`

Analyse up to 20 passwords in a single request.

**Rate limit:** 5 requests / minute

```bash
curl -X POST http://127.0.0.1:5000/bulk_check \
  -H "Content-Type: application/json" \
  -d '{"passwords": ["password", "hunter2", "Tr0ub4dor&3!"]}'
```

**Example response:**
```json
{
  "count": 3,
  "results": [
    {"index": 0, "score": 0, "strength": "Very Weak", "...": "..."},
    {"index": 1, "score": 0, "strength": "Very Weak", "...": "..."},
    {"index": 2, "score": 4, "strength": "Very Strong", "...": "..."}
  ]
}
```

Each `results` entry contains the same fields as `/check_strength`. Invalid entries return `{"index": N, "error": "..."}` instead.

---

## Rate Limits

| Endpoint             | Limit            |
|----------------------|------------------|
| Global default       | 500/day, 100/hour |
| `POST /check_strength`   | 30/minute    |
| `POST /generate_password` | 20/minute   |
| `POST /check_breach`     | 10/minute    |
| `POST /bulk_check`       | 5/minute     |

Rate-limited responses return HTTP 429:
```json
{"error": "Rate limit exceeded. Please slow down."}
```

---

## Error Responses

All errors return JSON with an `"error"` key:

| Status | Meaning                                    |
|--------|--------------------------------------------|
| 400    | Bad request (missing/invalid field, wrong type, too long) |
| 404    | Endpoint not found                         |
| 405    | Method not allowed                         |
| 429    | Rate limit exceeded                        |
| 503    | External service (HIBP) unavailable        |

---

## Running Tests

```bash
python -m pytest tests/ -v
```

96 tests covering: all 5 endpoints, input validation, response field shapes, breach mock (breached/clean/error), bulk mixed-input, rate limiter isolation, Shannon entropy, charset entropy, character analysis, policy checks, password generator (all parameter combinations, ambiguous exclusion, uniqueness).

---

## Contributing

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes and push.
4. Open a pull request.

---

## License

MIT License.
