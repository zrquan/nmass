import ctypes
import os
import string
from functools import wraps

from nmass.errors import NmapArgumentError


def as_root(func):
    """Decorator to ensure the decorated function is executed with root/administrator privileges.

    :param func: Function that requires elevated privileges to run.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if os.name == "nt":
            # Windows OS: Check for administrator privileges
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                is_admin = False
            if is_admin:
                return func(*args, **kwargs)
            else:
                raise PermissionError(f"{func.__name__} needs to be executed as an administrator.")
        else:
            # Unix-like OS: Check for root privileges
            if os.getuid() == 0:
                return func(*args, **kwargs)
            else:
                raise PermissionError(f"{func.__name__} needs to be executed as root.")

    return wrapper


def validate_target(target: str) -> None:
    """
    copy from https://github.com/savon-noir/python-libnmap/blob/37092bd825eeccaf3081b15b25f23294a94cf1ac/libnmap/process.py#L488
    """
    allowed_characters = frozenset(string.ascii_letters + string.digits + "-.:/% ")
    if not set(target).issubset(allowed_characters):
        raise NmapArgumentError(f"Target '{target}' contains invalid characters", "target")
    elif target.startswith("-") or target.endswith("-"):
        raise NmapArgumentError(
            f"Target '{target}' cannot begin or end with a dash ('-')", "target"
        )
