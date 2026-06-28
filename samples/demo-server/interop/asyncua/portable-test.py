#!/usr/bin/env python3
"""Portable asyncua smoke test for an already-running OPC UA server.

The full asyncua-test.py script targets the async-opcua demo namespace. This
script intentionally avoids demo-specific nodes so it can check other server
implementations from the same interop harness.
"""
import asyncio
import datetime
import sys

from asyncua import Client, ua
from asyncua.ua.uaerrors import UaStatusCodeError

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://127.0.0.1:4855"

g_checks = 0
g_failures = 0


def check(name, ok, detail=None):
    global g_checks, g_failures
    g_checks += 1
    if ok:
        print(f"  \x1b[32mok\x1b[0m   {name}")
    else:
        g_failures += 1
        print(f"  \x1b[31mFAIL\x1b[0m {name}" + (f"  -- {detail}" if detail else ""))


def status_name(value):
    try:
        return ua.StatusCode(value).name
    except Exception:
        return str(value)


async def discovery_checks(endpoint):
    print("\n=== Discovery service ===")
    client = Client(endpoint)
    try:
        endpoints = await client.connect_and_get_server_endpoints()
        check("GetEndpoints returns at least one endpoint", len(endpoints) > 0, f"count={len(endpoints)}")
    except Exception as exc:
        check("GetEndpoints returns at least one endpoint", False, repr(exc))
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


async def read_checks(client):
    print("\n=== Attribute service: standard reads ===")
    current_time = await client.get_node(ua.NodeId(2258, 0)).read_value()
    check("read ServerStatus/CurrentTime (i=2258)",
          isinstance(current_time, datetime.datetime),
          type(current_time).__name__)

    state = await client.get_node(ua.NodeId(2259, 0)).read_value()
    check("read ServerStatus/State (i=2259)", state is not None, repr(state))

    namespace_array = await client.get_node(ua.NodeId(2255, 0)).read_value()
    check("read NamespaceArray (i=2255)",
          isinstance(namespace_array, (list, tuple)) and len(namespace_array) > 0,
          repr(namespace_array))


async def browse_checks(client):
    print("\n=== View service: standard browse ===")
    refs = await client.nodes.objects.get_children()
    check("browse Objects folder (i=85)", len(refs) > 0, f"refs={len(refs)}")


async def error_checks(client):
    print("\n=== Portable error path ===")
    try:
        await client.get_node(ua.NodeId(999999999, 0)).read_value()
        check("read unknown numeric NodeId returns BadNodeIdUnknown", False, "read succeeded")
    except UaStatusCodeError as exc:
        check("read unknown numeric NodeId returns BadNodeIdUnknown",
              exc.code == ua.StatusCodes.BadNodeIdUnknown,
              status_name(exc.code))


async def main():
    print(f"asyncua portable interop smoke test against {ENDPOINT}")
    await discovery_checks(ENDPOINT)

    client = Client(ENDPOINT)
    await client.connect()
    try:
        check("anonymous session activates", True)
        await read_checks(client)
        await browse_checks(client)
        await error_checks(client)
    except Exception as exc:
        check("client ran without unhandled exception", False, repr(exc))
    finally:
        await client.disconnect()

    print(f"\n{g_checks - g_failures}/{g_checks} checks passed")
    sys.exit(g_failures)


if __name__ == "__main__":
    asyncio.run(main())
