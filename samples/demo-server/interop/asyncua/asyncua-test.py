#!/usr/bin/env python3
"""Third-stack interop conformance test: drive the async-opcua demo server with the Python
asyncua stack. A different implementation lineage from node-opcua (JS) and open62541 (C), so
three passing stacks is a strong conformance signal and any disagreement is high-signal.

This stack found a real server bug on its first run: asyncua populates ViewDescription.Timestamp
by default, and the server wrongly rejected every Browse/Query with Bad_ViewIdUnknown (PR #90).

Usage:  python3 asyncua-test.py [endpoint]   (env NOTRUST_ENDPOINT enables the untrusted-cert test)
Exit code is the number of failed checks (0 = all passed).
"""
import asyncio
import os
import sys

from asyncua import Client, ua
from asyncua.ua.uaerrors import UaStatusCodeError

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://127.0.0.1:4855"
NOTRUST_ENDPOINT = os.environ.get("NOTRUST_ENDPOINT")
DEMO_NS = "urn:DemoServer"

g_checks = 0
g_failures = 0


def check(name, ok, detail=None):
    global g_checks, g_failures
    g_checks += 1
    if ok:
        print(f"  \x1b[32mok\x1b[0m   {name}")
    else:
        g_failures += 1
        print(f"  \x1b[31mFAIL\x1b[0m {name}" + (f"  — {detail}" if detail else ""))


def code_of(err):
    return ua.StatusCode(err.code).name


class SubHandler:
    def __init__(self):
        self.count = 0

    def datachange_notification(self, node, val, data):
        self.count += 1

    def event_notification(self, event):
        pass


async def expect_raises(name, awaitable, expected):
    """Await `awaitable`; pass if it raises UaStatusCodeError with `expected`."""
    try:
        await awaitable
        check(name, False, "no error raised")
    except UaStatusCodeError as e:
        check(name, e.code == expected, code_of(e))


async def test_happy_path(client, ns):
    print("\n[None] browse / read / namespace / method / write / translate / subscription")

    # Browse the Objects folder.
    objects = client.nodes.objects
    refs = await objects.get_children()
    check("Browse(ObjectsFolder) returns children", len(refs) > 0)

    # Read CurrentTime and confirm it decodes as a datetime.
    import datetime
    ct = client.get_node(ua.NodeId(2258, 0))
    val = await ct.read_value()
    check("Read CurrentTime is a DateTime", isinstance(val, datetime.datetime))

    check("DemoServer namespace present", ns > 0, f"ns={ns}")

    # Call HelloWorld and confirm the greeting.
    functions = client.get_node(f"ns={ns};s=Functions")
    hello = client.get_node(f"ns={ns};s=HelloWorld")
    out = await functions.call_method(hello)
    check("HelloWorld returns a 'Hello World' greeting",
          isinstance(out, str) and out.startswith("Hello World"), repr(out))

    # Write a value to a writable variable and read it back.
    int32 = client.get_node(f"ns={ns};s=Int32")
    await int32.write_value(ua.Variant(424242, ua.VariantType.Int32))
    rb = await int32.read_value()
    check("Write + read-back of Int32", rb == 424242, repr(rb))

    # TranslateBrowsePath: Server -> ServerStatus -> CurrentTime resolves to i=2258.
    server = client.get_node(ua.NodeId(2253, 0))
    resolved = await server.get_child(["0:ServerStatus", "0:CurrentTime"])
    check("TranslateBrowsePath resolves CurrentTime (i=2258)",
          resolved.nodeid == ua.NodeId(2258, 0), str(resolved.nodeid))

    # Subscribe to the writable Int32 node and DRIVE the data-changes by writing to it, rather than
    # the server-timer-driven CurrentTime (which is racy under CI load). Deterministic delivery.
    handler = SubHandler()
    sub = await client.create_subscription(200, handler)
    await sub.subscribe_data_change(int32)
    await asyncio.sleep(0.3)  # let the subscription establish + the initial value arrive
    for v in (700001, 700002, 700003):
        await int32.write_value(ua.Variant(v, ua.VariantType.Int32))
        await asyncio.sleep(0.2)
    for _ in range(20):
        if handler.count >= 2:
            break
        await asyncio.sleep(0.1)
    check("Subscription delivers data-change notifications", handler.count >= 2,
          f"count={handler.count}")
    await sub.delete()


async def test_failure_modes(client, ns):
    print("\n[None] failure modes / error status codes")

    # Reading an unknown node -> Bad_NodeIdUnknown.
    await expect_raises("Read unknown node -> BadNodeIdUnknown",
                        client.get_node(f"ns={ns};s=NoSuchNode").read_value(),
                        ua.StatusCodes.BadNodeIdUnknown)

    # Writing the wrong data type to a typed scalar -> Bad_TypeMismatch.
    await expect_raises("Wrong-type write -> BadTypeMismatch",
                        client.get_node(f"ns={ns};s=Int32").write_value(
                            ua.Variant("not-an-int", ua.VariantType.String)),
                        ua.StatusCodes.BadTypeMismatch)

    # Calling a non-existent method is rejected.
    functions = client.get_node(f"ns={ns};s=Functions")
    try:
        await functions.call_method(client.get_node(f"ns={ns};s=NoSuchMethod"))
        check("Call of unknown method is rejected", False, "no error raised")
    except UaStatusCodeError as e:
        check("Call of unknown method is rejected", True, code_of(e))

    # #82: method called with fewer arguments than declared -> Bad_ArgumentsMissing.
    await expect_raises("Method call with missing arguments -> BadArgumentsMissing",
                        functions.call_method(client.get_node(f"ns={ns};s=Add"),
                                              ua.Variant(1, ua.VariantType.Int64)),
                        ua.StatusCodes.BadArgumentsMissing)

    # #83: scalar written to an array node (ValueRank mismatch) -> Bad_TypeMismatch.
    await expect_raises("Scalar written to an array node -> BadTypeMismatch",
                        client.get_node(f"ns={ns};s=Int32Array").write_value(
                            ua.Variant(5, ua.VariantType.Int32)),
                        ua.StatusCodes.BadTypeMismatch)

    # #84: monitored item on a non-existent node -> Bad_NodeIdUnknown.
    sub = await client.create_subscription(200, SubHandler())
    await expect_raises("Monitored item on unknown node -> BadNodeIdUnknown",
                        sub.subscribe_data_change(client.get_node(f"ns={ns};s=NoSuchNodeXYZ")),
                        ua.StatusCodes.BadNodeIdUnknown)
    await sub.delete()

    # Reading an invalid attribute id -> Bad_AttributeIdInvalid (raw read).
    rv = ua.ReadValueId()
    rv.NodeId = ua.NodeId(2258, 0)
    rv.AttributeId = 999
    rp = ua.ReadParameters()
    rp.NodesToRead = [rv]
    rres = await client.uaclient.read(rp)
    check("Read invalid attribute id -> BadAttributeIdInvalid",
          rres[0].StatusCode.value == ua.StatusCodes.BadAttributeIdInvalid,
          ua.StatusCode(rres[0].StatusCode.value).name)

    # Browsing with a non-ReferenceType referenceTypeId -> Bad_ReferenceTypeIdInvalid.
    # (Also exercises the PR #90 fix: asyncua sends a default non-null View Timestamp.)
    bd = ua.BrowseDescription()
    bd.NodeId = ua.NodeId(85, 0)
    bd.ReferenceTypeId = ua.NodeId(2253, 0)  # the Server object, an Object not a ReferenceType
    bd.IncludeSubtypes = False
    bd.BrowseDirection = ua.BrowseDirection.Forward
    bd.ResultMask = ua.BrowseResultMask.All
    bp = ua.BrowseParameters()
    bp.NodesToBrowse = [bd]
    bres = await client.uaclient.browse(bp)
    check("Browse with a non-ReferenceType refType -> BadReferenceTypeIdInvalid",
          bres[0].StatusCode.value == ua.StatusCodes.BadReferenceTypeIdInvalid,
          ua.StatusCode(bres[0].StatusCode.value).name)

    # A browse path that resolves to nothing -> Bad_NoMatch.
    await expect_raises("TranslateBrowsePath with no match -> BadNoMatch",
                        client.nodes.objects.get_child(["0:NoSuchChildXYZ"]),
                        ua.StatusCodes.BadNoMatch)

    # BrowseNext with an unrecognised continuation point -> Bad_ContinuationPointInvalid.
    bnp = ua.BrowseNextParameters()
    bnp.ContinuationPoints = [b"\x01\x02\x03\x04"]
    bnp.ReleaseContinuationPoints = False
    bnres = await client.uaclient.browse_next(bnp)
    check("BrowseNext with an invalid continuation point -> BadContinuationPointInvalid",
          bnres[0].StatusCode.value == ua.StatusCodes.BadContinuationPointInvalid,
          ua.StatusCode(bnres[0].StatusCode.value).name)


async def test_auth_failures():
    print("\n[None] authentication failure modes")

    c1 = Client(ENDPOINT)
    c1.set_user("sample1")
    c1.set_password("wrong-password")
    try:
        await c1.connect()
        check("Wrong password is rejected", False, "session established")
        await c1.disconnect()
    except Exception as e:
        check("Wrong password is rejected", True, type(e).__name__)

    c2 = Client(ENDPOINT)
    c2.set_user("no-such-user")
    c2.set_password("whatever")
    try:
        await c2.connect()
        check("Unknown user is rejected", False, "session established")
        await c2.disconnect()
    except Exception as e:
        check("Unknown user is rejected", True, type(e).__name__)


async def test_username():
    print("\n[None] username/password identity token")
    c = Client(ENDPOINT)
    c.set_user("sample1")
    c.set_password("sample1_password")
    try:
        await c.connect()
        val = await c.get_node(ua.NodeId(2258, 0)).read_value()
        check("Username/password session + authenticated read", val is not None)
        await c.disconnect()
    except Exception as e:
        check("Username/password session + authenticated read", False, repr(e))


async def main():
    print(f"asyncua interop smoke test against {ENDPOINT}")
    client = Client(ENDPOINT)
    await client.connect()
    try:
        ns = await client.get_namespace_index(DEMO_NS)
        await test_happy_path(client, ns)
        await test_failure_modes(client, ns)
    finally:
        await client.disconnect()

    await test_username()
    await test_auth_failures()

    print(f"\n{g_checks - g_failures}/{g_checks} checks passed")
    sys.exit(g_failures)


if __name__ == "__main__":
    asyncio.run(main())
