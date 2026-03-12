from .client import Github


class _Token:
    """Stub for github.Auth.Token."""
    def __init__(self, token: str):
        self.token = token


class Auth:
    """Stub for github.Auth namespace."""
    Token = _Token


__all__ = ["Auth", "Github"]
