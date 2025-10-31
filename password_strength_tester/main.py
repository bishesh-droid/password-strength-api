from flask import Flask, request, jsonify
from zxcvbn import zxcvbn

app = Flask(__name__)

@app.route('/check_strength', methods=['POST'])
def check_strength():
    """
    Checks the strength of a password.
    ---
    tags:
      - Password Strength
    parameters:
      - name: password
        in: body
        type: string
        required: true
        description: The password to check.
    responses:
      200:
        description: The strength of the password.
        schema:
          type: object
          properties:
            score:
              type: integer
              description: The password strength score (0-4).
            strength:
              type: string
              description: The password strength level.
            feedback:
              type: array
              items:
                type: string
              description: Suggestions for improving the password.
    """
    password = request.json.get('password')
    if not password:
        return jsonify({'error': 'Password is required.'}), 400

    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']['suggestions']

    strength_levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Medium",
        3: "Strong",
        4: "Very Strong"
    }
    strength = strength_levels.get(score, "Unknown")

    with open('/home/duffer/Gemini/password-strength-tester/results/results.txt', 'a') as f:
        f.write(f"Password: {password}\n")
        f.write(f"Score: {score}\n")
        f.write(f"Strength: {strength}\n")
        f.write(f"Feedback: {feedback}\n")
        f.write("-" * 20 + "\n")

    return jsonify({
        'score': score,
        'strength': strength,
        'feedback': feedback
    })

if __name__ == '__main__':
    app.run(debug=True)