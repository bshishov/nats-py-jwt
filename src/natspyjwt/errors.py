__all__ = [
    "JwtError",
    "JwtDecodeError",
    "JwtInvalidHeaderError",
    "JwtInvalidClaimError",
]


class JwtError(Exception):
    pass


class JwtDecodeError(JwtError):
    pass


class JwtInvalidClaimError(JwtError):
    pass


class JwtInvalidHeaderError(JwtError):
    pass
