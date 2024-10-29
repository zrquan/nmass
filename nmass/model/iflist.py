from typing import Literal, Optional, Union

from pydantic import BaseModel, IPvAnyAddress


class Interface(BaseModel):
    device: str
    short: str
    ip: Union[IPvAnyAddress, Literal["(none)"]]
    ip_mask: int
    type_: str
    is_up: bool
    mtu: int
    mac: Optional[str] = None


class Route(BaseModel):
    dest_ip: IPvAnyAddress
    dest_ip_mask: int
    device: str
    metric: int
    gateway: Optional[IPvAnyAddress] = None


class InterfaceList(BaseModel):
    interfaces: list[Interface]
    routes: list[Route]
