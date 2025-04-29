from typing import Literal

from pydantic import BaseModel, IPvAnyAddress


class Interface(BaseModel):
    device: str
    short: str
    ip: IPvAnyAddress | Literal["(none)"]
    ip_mask: int
    type_: str
    is_up: bool
    mtu: int
    mac: str | None = None


class Route(BaseModel):
    dest_ip: IPvAnyAddress
    dest_ip_mask: int
    device: str
    metric: int
    gateway: IPvAnyAddress | None = None


class InterfaceList(BaseModel):
    interfaces: list[Interface]
    routes: list[Route]
