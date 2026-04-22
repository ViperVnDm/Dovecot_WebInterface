"""Shared rate limiter instance.

Defined in its own module so route handlers can decorate themselves
without creating a circular import on `app.main`.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address


limiter = Limiter(key_func=get_remote_address)
