import jwt
from datetime import datetime, timedelta
from dateutil import tz

def sign(payload, expiry_ttl_in_minutes, private_key, timezone):
  now = datetime.now(timezone)

  payload["expires"] = (now + timedelta(expiry_ttl_in_minutes)).isoformat()
  return jwt.encode(payload, private_key, algorithm='ES256')

def sign_dashboard_access_token(expiry_ttl_in_minutes, access_type, organisation_id, dashboard_id, user_reference, scope, private_key, timezone=tz.tzlocal()):
  return sign({
  "accessType": access_type,
  "organisationId": organisation_id,
  "dashboardId": dashboard_id,
  "userReference": user_reference,
  "scope": scope
}, expiry_ttl_in_minutes, private_key, timezone)

def sign_data_access_token(expiry_ttl_in_minutes, data_set_ids, secure_filters, private_key, timezone=tz.tzlocal()):
  return sign({
  "dataSetIds": data_set_ids,
  "secureFilters": secure_filters
}, expiry_ttl_in_minutes, private_key, timezone)
