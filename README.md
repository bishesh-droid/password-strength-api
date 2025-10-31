# Password Strength Tester

A web-based tool to check the strength of a password. This application provides a simple API to evaluate password strength and give feedback.

## Getting Started

### Prerequisites

* Python 3.6+
* pip

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/password-strength-tester.git
   cd password-strength-tester
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

1. Run the Flask application:
   ```bash
   python password_strength_tester/main.py
   ```

2. The application will be running at `http://127.0.0.1:5000`.

### API Usage

Send a POST request to `/check_strength` with a JSON body containing the password:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"password": "your_password"}' http://127.0.0.1:5000/check_strength
```

**Example Response:**

```json
{
  "score": 4,
  "strength": "Very Strong",
  "feedback": []
}
```

## Running Tests

To run the tests, execute the following command:

```bash
python tests/test_main.py
```# password-strength-api
