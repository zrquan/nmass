import asyncio
import textwrap
from typing import Annotated
from uuid import UUID, uuid4

from fastmcp import Context, FastMCP
from pydantic import Field

from nmass.masscan import Masscan
from nmass.model.elements import NmapRun
from nmass.nmap import Nmap

mcp: FastMCP = FastMCP("nmass", instructions="This server can use nmap and masscan for port scanning.")
scan_results: dict[UUID, NmapRun] = {}


@mcp.resource("nmass://scan/results", description="Get all available scan results", mime_type="application/json")
def list_all_results() -> list[str]:
    return [v.model_dump_json(exclude_none=True) for _, v in scan_results.items()]


# TODO: https://nmap.org/nsedoc/scripts/
async def fetch_nmap_script_docs() -> None: ...


@mcp.tool(description="Get available scan result by ID")
def get_scan_result(scan_id: UUID) -> str:
    if result := scan_results.get(scan_id):
        return result.model_dump_json(exclude_none=True)
    else:
        raise ValueError(f"Result {scan_id} not found")


@mcp.tool(description="Use nmap to scan targets")
async def scan_by_nmap(
    ctx: Context,
    target: str,
    ports: Annotated[list[int] | None, Field(description="Only scan specified ports")] = None,
    top_ports: Annotated[int | None, Field(description="Scan the most common ports")] = None,
    scripts: Annotated[list[str] | None, Field(description="Nmap scripts")] = None,
    timeout: float | None = None,
) -> dict[UUID, str] | None:
    scan_id = uuid4()
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
        assert result is not None
    except asyncio.TimeoutError:
        await ctx.warning("Scanning timeout")
        return None
    except Exception as e:
        await ctx.error(str(e))
        return None
    else:
        scan_results[scan_id] = result
        return {scan_id: result.model_dump_json(exclude_none=True)}


@mcp.tool(description="Use masscan to scan targets")
async def scan_by_masscan(
    ctx: Context,
    target: Annotated[
        str,
        Field(
            description="There are three valid formats. IPv4 address, range like 10.0.0.1-10.0.0.100, and CIDR address"
        ),
    ],
    ports: Annotated[list[int], Field(description="Target's ports")],
    rate: Annotated[int | None, Field(description="Rate for transmitting packets")] = None,
    timeout: Annotated[float | None, Field(description="Scan timeout second")] = None,
) -> dict[UUID, str] | None:
    scan_id = uuid4()
    try:
        await ctx.info(f"Scanning {target} by masscan, {scan_id=}")
        masscan = Masscan().with_targets(target).with_ports(*ports).with_banners()
        if rate:
            masscan.with_rate(rate)
        result = await masscan.arun(timeout)
        assert result is not None
    except asyncio.TimeoutError:
        await ctx.warning("Scanning timeout")
        return None
    except Exception as e:
        await ctx.error(str(e))
        return None
    else:
        scan_results[scan_id] = result
        return {scan_id: result.model_dump_json(exclude_none=True)}


@mcp.prompt(description="Prompts LLM to analyze the scan result")
def analyse_result(scan_id: UUID) -> str:
    if result := scan_results.get(scan_id):
        return textwrap.dedent(f"""\
            I want you to act as a cybersecurity analysis assistant specialized in port scanning results.
            I will provide result from masscan/nmap scans in JSON FORMAT.
            Analyze open ports, service banners, and version information to identify:
              1. Known vulnerabilities associated with specific service versions
              2. Potentially risky services (e.g., unencrypted protocols, deprecated technologies)
              3. Common misconfigurations based on service type
              4. Indicators of exposed administrative interfaces
              5. Services with publicly available exploit PoCs
            Present findings in a structured format: [Port/Protocol] [Service] [Risk Level] [Risk Description].
            Reference CVE numbers when applicable. Exclude mitigation suggestions unless explicitly requested.

            The scan result is:
              {result.model_dump_json(exclude_none=True)}""")
    else:
        raise ValueError(f"Result {scan_id} not found")


if __name__ == "__main__":
    mcp.run()
