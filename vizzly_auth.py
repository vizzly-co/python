import jwt
from datetime import datetime, timedelta

def sign(payload, expiry_ttl_in_minutes, private_key):
  now = datetime.today()
  
  payload["expires"] = (now + timedelta(minutes=5)).isoformat()
  return jwt.encode(payload, private_key, algorithm='ES256')

def sign_dashboard_access_token(expiry_ttl_in_minutes, access_type, organisation_id, dashboard_id, user_reference, private_key):
  return sign({
  "accessType": access_type,
  "organisationId": organisation_id,
  "dashboardId": dashboard_id,
  "userReference": user_reference,
}, expiry_ttl_in_minutes, private_key)

def sign_data_access_token(expiry_ttl_in_minutes, data_set_ids, secure_filters, private_key):
  return sign({
  "dataSetIds": data_set_ids,
  "secureFilters": secure_filters
}, expiry_ttl_in_minutes, private_key)
