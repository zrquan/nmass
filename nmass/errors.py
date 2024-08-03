class NmapNotInstalledError(Exception):
    def __init__(
        self,
        message: str = "The nmap executable could not be found, please install nmap first",
    ) -> None:
        super().__init__(message)


class NmapArgumentError(Exception):
    def __init__(self, message: str, nmap_arg: str) -> None:
        super().__init__(message, nmap_arg)


class NmapExecutionError(Exception):
    def __init__(self, message: str, retcode: int) -> None:
        super().__init__(message, retcode)


class MasscanNotInstalledError(Exception):
    def __init__(
        self,
        message: str = "The masscan executable could not be found, please install masscan first",
    ) -> None:
        super().__init__(message)


class MasscanArgumentError(Exception):
    def __init__(self, message: str, masscan_arg: str) -> None:
        super().__init__(message, masscan_arg)


class MasscanExecutionError(Exception):
    def __init__(self, message: str, retcode: int) -> None:
        super().__init__(message, retcode)
