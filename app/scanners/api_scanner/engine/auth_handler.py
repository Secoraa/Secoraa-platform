# engine/auth_handler.py

def build_auth_headers(token: str = None):
    if not token:
        return {}

    return {
        "Authorization": f"Bearer {token}"
    }
