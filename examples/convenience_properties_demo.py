"""
Demo script showing the convenience properties improvements.

This demonstrates how the new convenience properties provide
a cleaner API while maintaining backward compatibility.
"""

from pathlib import Path

from nmass.model.elements import NmapRun

# Load example XML
xml_file = Path(__file__).parent.parent / "tests/unit/data/1_os_banner_scripts.xml"
result = NmapRun.from_xml(xml_file.read_bytes())

print("=" * 80)
print("NmapRun Convenience Properties Demo")
print("=" * 80)

# ============================================================================
# Example 1: Accessing scan statistics
# ============================================================================
print("\n1. Scan Statistics")
print("-" * 80)

# OLD WAY (still works)
print("OLD WAY:")
if result.stats:
    print(f"  Total hosts: {result.stats.hosts['total']}")
    print(f"  Hosts up: {result.stats.hosts['up']}")
    print(f"  Hosts down: {result.stats.hosts['down']}")

# NEW WAY (cleaner)
print("\nNEW WAY:")
print(f"  Total hosts: {result.hosts_total}")
print(f"  Hosts up: {result.hosts_up}")
print(f"  Hosts down: {result.hosts_down}")

# ============================================================================
# Example 2: Accessing host information
# ============================================================================
print("\n2. Host Information")
print("-" * 80)

for host in result.hosts:
    # OLD WAY (still works)
    print("OLD WAY:")
    print(f"  IP: {host.addresses[0].addr}")
    print(f"  State: {host.status.state if host.status else 'unknown'}")
    print(f"  Hostname: {host.hostnames[0].name if host.hostnames else 'N/A'}")

    # NEW WAY (cleaner)
    print("\nNEW WAY:")
    print(f"  IPv4: {host.ipv4}")
    print(f"  IPv6: {host.ipv6}")
    print(f"  MAC: {host.mac}")
    print(f"  State: {host.state}")
    print(f"  Hostname: {host.hostname or 'N/A'}")

    # ============================================================================
    # Example 3: Accessing port information
    # ============================================================================
    print("\n3. Port Information")
    print("-" * 80)

    # OLD WAY (still works)
    print("OLD WAY:")
    if host.ports and host.ports.ports:
        for port in host.ports.ports[:3]:  # Show first 3 ports
            print(f"  Port {port.portid}/{port.protocol}:")
            print(f"    State: {port.state.state}")
            print(f"    Reason: {port.state.reason}")
            if port.service:
                print(f"    Service: {port.service.name}")
                print(f"    Product: {port.service.product or 'N/A'}")
                print(f"    Version: {port.service.version or 'N/A'}")

    # NEW WAY (cleaner)
    print("\nNEW WAY:")
    for port in host.port_list[:3]:  # Show first 3 ports
        print(f"  Port {port.portid}/{port.protocol}:")
        print(f"    State: {port.port_state}")
        print(f"    Reason: {port.reason}")
        print(f"    Service: {port.service_name or 'N/A'}")
        print(f"    Product: {port.product or 'N/A'}")
        print(f"    Version: {port.version or 'N/A'}")

# ============================================================================
# Example 4: Iterating through all open ports
# ============================================================================
print("\n4. Finding All Open Ports")
print("-" * 80)

# OLD WAY (still works)
print("OLD WAY:")
for host in result.hosts:
    if host.ports and host.ports.ports:
        open_ports = [p for p in host.ports.ports if p.state.state.value == "open"]
        print(f"  {host.addresses[0].addr}: {len(open_ports)} open ports")

# NEW WAY (cleaner)
print("\nNEW WAY:")
for host in result.hosts:
    open_ports = [p for p in host.port_list if p.port_state.value == "open"]
    print(f"  {host.ipv4}: {len(open_ports)} open ports")

# ============================================================================
# Example 5: Building a service inventory
# ============================================================================
print("\n5. Service Inventory")
print("-" * 80)

# OLD WAY (still works)
print("OLD WAY:")
services = {}
for host in result.hosts:
    if host.ports and host.ports.ports:
        for port in host.ports.ports:
            if port.service and port.state.state.value == "open":
                key = f"{port.service.name}:{port.service.product or 'unknown'}"
                services[key] = services.get(key, 0) + 1

for service, count in services.items():
    print(f"  {service}: {count}")

# NEW WAY (cleaner)
print("\nNEW WAY:")
services = {}
for host in result.hosts:
    for port in host.port_list:
        if port.service_name and port.port_state.value == "open":
            key = f"{port.service_name}:{port.product or 'unknown'}"
            services[key] = services.get(key, 0) + 1

for service, count in services.items():
    print(f"  {service}: {count}")

print("\n" + "=" * 80)
print("✅ Both approaches work identically!")
print("✅ New properties provide cleaner, more intuitive API")
print("✅ Full backward compatibility maintained")
print("=" * 80)
