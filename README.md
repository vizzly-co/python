# Vizzly Python library

Python library to generate dashboard and data access tokens used for vizzly.co.

## Installation
```sh
pip3 install git+https://github.com/vizzly-co/auth-python3.git#egg=vizzly
```

## Usage
```python3
import vizzly

private_key = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMd64JFtp7nbYIsws03dy6fBirhpio4aLwPdW/6Xg1WRoAoGCCqGSM49
AwEHoUQDQgAERbmqmGHbjlNMXjHZMJsoFsDnQDT7k4aV5wBdlXIKe0GH+FWSwawt
c8XAMURwSA7iAY2QzmzJ4RQ6ZKp1UVkpLA==
-----END EC PRIVATE KEY-----
"""

dashboard_access_token = vizzly.sign_dashboard_access_token(
  expiry_ttl_in_minutes=60,
  access_type='editor',
  organisation_id='org_123',
  dashboard_id='dsh_123',
  user_reference='usr-1',
  private_key=private_key
)

data_access_token = vizzly.sign_data_access_token(
  expiry_ttl_in_minutes=20,
  data_set_ids='*',
  secure_filters={},
  private_key=private_key
)
```

### Website
https://vizzly.co

### Docs
https://docs.vizzly.co
