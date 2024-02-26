import unittest
import vizzly.auth as auth
import jwt
from unittest import mock
from datetime import timezone

class TestAuth(unittest.TestCase):
  def test_sign(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign({"foo": "bar"}, 60, private_key, timezone.utc)

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["foo"] == "bar"
        assert "expires" in decoded
        assert decoded['expires'].endswith("+00:00")

  def test_sign_dashboard_access_token(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_dashboard_access_token(
        expiry_ttl_in_minutes=20,
        access_type='admin',
        project_id='prj_123',
        user_reference='usr-123',
        scope="read",
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["accessType"] == "admin"
        assert decoded["projectId"] == "prj_123"
        assert decoded["userReference"] == "usr-123"
        assert decoded.get("parentDashboardIds") == None
        assert decoded["scope"] == "read"
        assert "expires" in decoded
        assert "+" in decoded['expires']

  def test_sign_dashboard_access_token_with_parent_dashboards(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_dashboard_access_token(
        expiry_ttl_in_minutes=20,
        access_type='admin',
        project_id='prj_123',
        user_reference='usr-123',
        scope="read",
        parent_dashboard_ids=["dsh_12345"],
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["accessType"] == "admin"
        assert decoded["projectId"] == "prj_123"
        assert decoded["userReference"] == "usr-123"
        assert decoded["scope"] == "read"
        assert decoded.get("parentDashboardIds") == ["dsh_12345"]
        assert "expires" in decoded
        assert "+" in decoded['expires']

  def test_sign_dashboard_access_token_with_all_defaults(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_dashboard_access_token(
        expiry_ttl_in_minutes=20,
        project_id='prj_123',
        user_reference='usr-123',
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["accessType"] == "standard"
        assert decoded["projectId"] == "prj_123"
        assert decoded["userReference"] == "usr-123"
        assert decoded["scope"] == "read_write"
        assert decoded.get("parentDashboardIds") == None
        assert "expires" in decoded
        assert "+" in decoded['expires']

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

        assert decoded["parameters"] == {}
        assert decoded["dataSetIds"] == "*"
        assert decoded["secureFilters"] == {
          "das_1": [{
            "field": "fie_1",
            "op": "=",
            "value": "usr_12345"
          }]
        }
        assert "expires" in decoded
        assert "+" in decoded['expires']

  def test_sign_data_access_token_with_parameters(self):
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
        parameters={"something": "secret"},
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["parameters"] == {"something": "secret"}

  def test_sign_query_engine_access_token(self):
    with open('private_key.pem', 'r') as f:
      private_key = f.read()
      token = auth.sign_query_engine_access_token(
        expiry_ttl_in_minutes=20,
        allow_data_preview_access=True,
        allow_database_schema_access=True,
        private_key=private_key
      )

      with open('public_key.pem', 'r') as f:
        public_key = f.read()
        decoded = jwt.decode(token, public_key, algorithms=['ES256'])

        assert decoded["allowDataPreviewAccess"] == True
        assert decoded["allowDatabaseSchemaAccess"] == True

        assert "expires" in decoded
        assert "+" in decoded['expires']
