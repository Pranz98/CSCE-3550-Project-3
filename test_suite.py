import unittest
from unittest.mock import patch, MagicMock
import json
from http.server import HTTPServer
from main import MyServer

class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('localhost', 8080), MyServer)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_auth_endpoint(self):
        with patch('main.jwt.encode') as mock_encode:
            mock_encode.return_value = b'token'
            response = self._send_request('/auth')
            self.assertEqual(response.status, 200)
            self.assertEqual(response.data, b'token')

    def test_expired_auth_endpoint(self):
        with patch('main.jwt.encode') as mock_encode:
            mock_encode.return_value = b'token'
            response = self._send_request('/auth?expired=true')
            self.assertEqual(response.status, 200)
            self.assertEqual(response.data, b'token')

    def test_register_endpoint(self):
        with patch('main.secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'password'
            data = {'username': 'testuser', 'email': 'test@example.com'}
            response = self._send_request('/register', 'POST', data)
            self.assertEqual(response.status, 200)
            self.assertIn(b'password', response.data)

    def test_register_endpoint_missing_data(self):
        data = {}
        response = self._send_request('/register', 'POST', data)
        self.assertEqual(response.status, 400)

    def test_register_endpoint_duplicate_username(self):
        with patch('main.secrets.token_urlsafe') as mock_token:
            mock_token.return_value = 'password'
            data = {'username': 'testuser', 'email': 'test@example.com'}
            self._send_request('/register', 'POST', data)
            response = self._send_request('/register', 'POST', data)
            self.assertEqual(response.status, 409)

    def test_register_endpoint_invalid_email(self):
        data = {'username': 'testuser', 'email': 'invalid-email'}
        response = self._send_request('/register', 'POST', data)
        self.assertEqual(response.status, 400)

    def test_jwks_endpoint(self):
        response = self._send_request('/.well-known/jwks.json')
        self.assertEqual(response.status, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)

    def test_invalid_endpoint(self):
        response = self._send_request('/invalid')
        self.assertEqual(response.status, 405)

    def _send_request(self, path, method='GET', data=None):
        import requests
        url = f'http://localhost:8080{path}'
        if method == 'GET':
            response = requests.get(url)
        elif method == 'POST':
            response = requests.post(url, json=data)
        return response

if __name__ == '__main__':
    unittest.main()
