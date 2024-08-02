import os
from functools import wraps


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
