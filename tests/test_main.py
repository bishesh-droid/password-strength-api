import unittest
import json
from password_strength_tester.main import app

class TestPasswordStrength(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()

    def test_check_strength_no_password(self):
        response = self.app.post('/check_strength', data=json.dumps({}), content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Password is required.')

    def test_check_strength_weak_password(self):
        response = self.app.post('/check_strength', data=json.dumps({'password': 'password'}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['strength'], 'Very Weak')

    def test_check_strength_strong_password(self):
        response = self.app.post('/check_strength', data=json.dumps({'password': 'MyP@ssw0rd123!'}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['strength'], 'Very Strong')

if __name__ == '__main__':
    unittest.main()