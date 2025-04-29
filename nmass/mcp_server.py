import asyncio
import uuid
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from nmass.masscan import Masscan
from nmass.model.elements import NmapRun
from nmass.nmap import Nmap

mcp = FastMCP("nmass", instructions="This server can use nmap and masscan for port scanning.")
scan_results: dict[str, NmapRun] = {}


@mcp.resource("nmass://scan/{scan_id}")
def get_scan_result(scan_id: str) -> NmapRun:
    """Get available scan result by ID"""
    if result := scan_results.get(scan_id):
        return result
    else:
        raise ValueError(f"Result {scan_id} not found")


@mcp.resource("nmass://scan/results")
def get_all_results() -> list[NmapRun]:
    """Get all available scan results"""
    return [v for _, v in scan_results.items()]


# TODO: https://nmap.org/nsedoc/scripts/
async def fetch_nmap_script_docs() -> dict[str, str]: ...


@mcp.tool()
async def scan_by_nmap(
    ctx: Context,
    target: str,
    ports: Annotated[list[int] | None, Field(description="Only scan specified ports")] = None,
    top_ports: Annotated[int | None, Field(description="Scan the most common ports")] = None,
    scripts: Annotated[list[str] | None, Field(description="Nmap scripts")] = None,
    timeout: float | None = None,
) -> dict[str, str] | None:
    """Use nmap to scan target's ports.

    :return: Scan id and result.
    """
    scan_id = str(uuid.uuid4())
    try:
        await ctx.info(f"Scanning {target} by nmap, {scan_id=}")
        nmap = Nmap().with_targets(target).with_service_info().with_version_light()
        if ports:
            nmap.with_ports(*ports)
        elif top_ports:
            nmap.with_most_common_ports(top_ports)
        if scripts:
            nmap.with_scripts(*scripts)
        result = await nmap.arun(timeout)
    except asyncio.TimeoutError:
        await ctx.warning("Scanning timeout")
        return None
    except Exception as e:
        await ctx.error(str(e))
        return None
    else:
        scan_results[scan_id] = result
        return {scan_id: result.model_dump_json(exclude_none=True)}


@mcp.tool()
async def scan_by_masscan(
    ctx: Context,
    target: str,
    ports: list[int],
    rate: int | None = None,
    timeout: float | None = None,
) -> dict[str, str] | None:
    """Use masscan to scan target's ports.

    :param target: There are three valid formats. IPv4 address, range like "10.0.0.1-10.0.0.100", and CIDR address.
    :param ports: Target's ports.
    :param rate: Rate for transmitting packets.
    :param timeout: Scan timeout second, defaults to None.
    :return: Scan id and result.
    """
    scan_id = str(uuid.uuid4())
    try:
        await ctx.info(f"Scanning {target} by masscan, {scan_id=}")
        masscan = Masscan().with_targets(target).with_ports(*ports).with_banners()
        if rate:
            masscan.with_rate(rate)
        result = await masscan.arun(timeout)
    except asyncio.TimeoutError:
        await ctx.warning("Scanning timeout")
        return None
    except Exception as e:
        await ctx.error(str(e))
        return None
    else:
        scan_results[scan_id] = result
        return {scan_id: result.model_dump_json(exclude_none=True)}


if __name__ == "__main__":
    mcp.run()
