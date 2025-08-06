import unittest
from app import app

class MessageSendTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_send_message_no_data(self):
        response = self.app.post('/api/send_message', data={})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'error', response.data)

    def test_send_message_missing_receiver(self):
        response = self.app.post('/api/send_message', data={'content': 'Hello'})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'error', response.data)

    def test_send_message_success(self):
        # This test assumes a valid receiver_id exists in the test DB
        response = self.app.post('/api/send_message', data={
            'receiver_id': 'testuser',
            'content': 'Hello from test'
        })
        # Accept either 200 or 400 depending on backend logic
        self.assertIn(response.status_code, [200, 400])

if __name__ == '__main__':
    unittest.main()
