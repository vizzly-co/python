# Vizzly python auth

Python library to generate dashboard and data access tokens used for vizzly.co.

## Installation
```sh
pip install git+https://github.com/vizzly-co/auth-python3.git#egg=vizzly
```

## Usage
```
FUNCTIONS
    sign_dashboard_access_token(expiry_ttl_in_minutes, access_type, organisation_id, dashboard_id, user_reference, private_key)

    sign_data_access_token(expiry_ttl_in_minutes, data_set_ids, secure_filters, private_key)
```

### Website
https://vizzly.co

### Docs
https://docs.vizzly.co
