import os
import string
from functools import wraps

from nmass.errors import NmapArgumentError


def as_root(func):
    """@as_root 装饰的函数需要高权限用户执行（比如 Linux 下的 root 用户）

    :param func: 需要 root 权限执行的函数
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # TODO:  Windows OS
        if os.getuid() == 0:
            return func(*args, **kwargs)
        else:
            raise PermissionError(f"{func=} need to execute as root")

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
