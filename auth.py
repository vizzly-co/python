import jwt
from datetime import datetime, timedelta

def sign(payload, expiry_ttl_in_minutes, private_key):
  now = datetime.today()
  
  payload["expires"] = (now + timedelta(minutes=5)).isoformat()
  return jwt.encode(payload, private_key, algorithm='ES256')

def sign_dashboard_access_token(expiry_ttl_in_minutes, access_type, organisation_id, dashboard_id, user_reference, private_key):
  signed_jwt = sign({
  "accessType": access_type,
  "organisationId": organisation_id,
  "dashboardId": dashboard_id,
  "userReference": user_reference,
}, expiry_ttl_in_minutes, private_key)
  return signed_jwt

# print("Dashboard access token")
# print(sign({
#   "accessType": "editor",
#   "organisationId": "org_9817c013a80944cea5890df34ab792cd",
#   "dashboardId": "dsh_c45df01b778a44bebd752a1e1b1f8942",
#   "userReference": "caa41942-1213-4317-8316-b9e422aad722_editor",
#   "expires": "2022-12-16T10:52:35.172Z"
# }, 'private_key.pem'))

# print("Data access token")
# print(sign({
#   "dataSetIds": "*",
#   "secureFilters": {
#     "custom-stock-data": []
#   },
#   "expires": "2022-12-16T10:52:35.171Z"}, 'private_key.pem'))