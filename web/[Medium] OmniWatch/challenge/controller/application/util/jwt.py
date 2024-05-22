import jwt

def create_jwt(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_jwt(token, secret):
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except Exception:
        return False