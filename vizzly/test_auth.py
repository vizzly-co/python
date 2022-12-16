import unittest
import vizzly.auth as auth
import jwt
from unittest import mock

class TestAuth(unittest.TestCase):
  def test_sign(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign({"foo": "bar"}, 60, private_key)

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["foo"] == "bar"
        assert "expires" in decoded

  def test_sign_dashboard_access_token(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_dashboard_access_token(
        expiry_ttl_in_minutes=20,
        access_type='editor',
        organisation_id='org_123',
        user_reference='usr-123',
        dashboard_id='dsh_432',
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["accessType"] == "editor"
        assert decoded["organisationId"] == "org_123"
        assert decoded["dashboardId"] == "dsh_432"
        assert decoded["userReference"] == "usr-123"
        assert "expires" in decoded

  def test_sign_data_access_token(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_data_access_token(
        expiry_ttl_in_minutes=20,
        data_set_ids="*",
        secure_filters={
          "das_1": [{
            "field": "fie_1",
            "op": "=",
            "value": "usr_12345"
          }]
        },
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["dataSetIds"] == "*"
        assert decoded["secureFilters"] == {
          "das_1": [{
            "field": "fie_1",
            "op": "=",
            "value": "usr_12345"
          }]
        }
        assert "expires" in decoded
