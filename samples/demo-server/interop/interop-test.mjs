// node-opcua interop conformance smoke test against the async-opcua demo server.
//
// Drives the running demo server with an independent OPC UA stack (node-opcua) across
// the conformance-relevant surface: discovery, secured + unsecured sessions, browse,
// read, method call, and subscription data-change delivery. This is the practical
// substitute for the official UACTT, which requires OPC Foundation corporate membership.
//
// Usage:  node interop-test.mjs <endpoint-url>
// Exit code is the number of failed checks (0 = all passed).

import {
  OPCUAClient,
  OPCUACertificateManager,
  MessageSecurityMode,
  SecurityPolicy,
  AttributeIds,
  TimestampsToReturn,
  MonitoringMode,
  ClientSubscription,
  ClientMonitoredItem,
  UserTokenType,
  DataType,
  VariantArrayType,
  NodeClass,
  StatusCodes,
  BrowseDirection,
  makeBrowsePath,
  DataChangeFilter,
  DataChangeTrigger,
  DeadbandType,
  HistoryReadRequest,
  ReadRawModifiedDetails,
  PublishRequest,
} from "node-opcua";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdirSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const endpoint = process.argv[2] || "opc.tcp://localhost:4855/";
// A companion server (set by run-interop.sh) that does not auto-trust client certs.
const NOTRUST_ENDPOINT = process.env.NOTRUST_ENDPOINT;

const CLIENT_APP_URI = "urn:async-opcua-interop-client";
const certFile = join(here, "client-pki", "own", "certs", "client_certificate.pem");

// A dedicated, auto-accepting certificate manager so the server's self-signed cert is
// trusted unattended. We explicitly generate the client certificate with a known
// applicationUri so the URI it declares in CreateSession matches its certificate SAN —
// otherwise the (correctly spec-conformant) server rejects it with BadCertificateUriInvalid.
let certificateManager;
let privateKeyFile;
async function setupClientCertificate() {
  certificateManager = new OPCUACertificateManager({
    rootFolder: join(here, "client-pki"),
    automaticallyAcceptUnknownCertificate: true,
  });
  await certificateManager.initialize();
  privateKeyFile = certificateManager.privateKey;
  mkdirSync(dirname(certFile), { recursive: true });
  await certificateManager.createSelfSignedCertificate({
    applicationUri: CLIENT_APP_URI,
    subject: "/CN=async-opcua-interop-client/O=async-opcua",
    dns: ["localhost"],
    ip: ["127.0.0.1"],
    startDate: new Date(),
    validity: 365,
    outputFile: certFile,
  });
}
const DEMO_NS = "urn:DemoServer";
const CURRENT_TIME = "i=2258"; // Server_ServerStatus_CurrentTime — changes every second.

let failures = 0;
let checks = 0;
function check(name, cond, detail = "") {
  checks++;
  if (cond) {
    console.log(`  \x1b[32mok\x1b[0m   ${name}`);
  } else {
    failures++;
    console.error(`  \x1b[31mFAIL\x1b[0m ${name}${detail ? "  — " + detail : ""}`);
  }
}

async function expectServiceFault(name, action, expected) {
  try {
    const response = await action();
    const sc = response && response.responseHeader && response.responseHeader.serviceResult;
    check(name, sc && sc.equals(expected), sc ? sc.toString() : "no service result");
  } catch (e) {
    check(name, e.message && e.message.includes(expected.name), e.message);
  }
}

function newClient(opts = {}) {
  return OPCUAClient.create({
    applicationName: "async-opcua-interop-client",
    applicationUri: CLIENT_APP_URI,
    clientCertificateManager: certificateManager,
    certificateFile: certFile,
    privateKeyFile,
    endpointMustExist: false,
    connectionStrategy: { maxRetry: 1, initialDelay: 200, maxDelay: 500 },
    ...opts,
  });
}

async function withSession(label, opts, fn, userIdentity) {
  const client = newClient(opts);
  try {
    await client.connect(endpoint);
    const session = userIdentity
      ? await client.createSession(userIdentity)
      : await client.createSession();
    try {
      await fn(session);
    } finally {
      await session.close();
    }
    await client.disconnect();
    return true;
  } catch (e) {
    check(`${label}: session established`, false, e.message);
    try {
      await client.disconnect();
    } catch {
      /* ignore */
    }
    return false;
  }
}

const SECURED = {
  securityMode: MessageSecurityMode.SignAndEncrypt,
  securityPolicy: SecurityPolicy.Basic256Sha256,
};

async function testDiscovery() {
  console.log("\n[discovery] GetEndpoints");
  const client = newClient();
  try {
    await client.connect(endpoint);
    const eps = await client.getEndpoints();
    await client.disconnect();
    check("GetEndpoints returns endpoints", eps.length > 0, `got ${eps.length}`);
    check(
      "None endpoint advertised",
      eps.some((e) => e.securityPolicyUri.endsWith("#None")),
    );
    check(
      "Basic256Sha256 SignAndEncrypt advertised",
      eps.some(
        (e) =>
          e.securityPolicyUri.includes("Basic256Sha256") &&
          e.securityMode === MessageSecurityMode.SignAndEncrypt,
      ),
    );
  } catch (e) {
    check("GetEndpoints", false, e.message);
    try {
      await client.disconnect();
    } catch {
      /* ignore */
    }
  }
}

async function testUnsecuredServices() {
  console.log("\n[None] browse / read / namespace / method / subscription");
  await withSession(
    "None",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      // Browse the Objects folder.
      const browse = await session.browse("ObjectsFolder");
      check(
        "Browse(ObjectsFolder) returns references",
        browse.references && browse.references.length > 0,
        `statusCode=${browse.statusCode.toString()}`,
      );

      // Read a standard node (CurrentTime).
      const dv = await session.read({ nodeId: CURRENT_TIME, attributeId: AttributeIds.Value });
      check("Read CurrentTime is Good", dv.statusCode.isGood(), dv.statusCode.toString());
      check("CurrentTime decodes as a DateTime", dv.value && dv.value.value instanceof Date);

      // Resolve the demo namespace and call the HelloWorld method.
      const nsArray = await session.readNamespaceArray();
      const nsIdx = nsArray.indexOf(DEMO_NS);
      check("DemoServer namespace present", nsIdx > 0, `nsArray=[${nsArray.join(", ")}]`);
      if (nsIdx > 0) {
        const result = await session.call({
          objectId: `ns=${nsIdx};s=Functions`,
          methodId: `ns=${nsIdx};s=HelloWorld`,
          inputArguments: [],
        });
        check("HelloWorld call is Good", result.statusCode.isGood(), result.statusCode.toString());
        const out =
          result.outputArguments &&
          result.outputArguments[0] &&
          result.outputArguments[0].value;
        check(
          "HelloWorld returns a 'Hello World' greeting",
          typeof out === "string" && out.startsWith("Hello World"),
          `got ${JSON.stringify(out)}`,
        );
      }

      // Subscription data-change delivery. Drive the changes from the client by writing distinct
      // values to a writable variable rather than relying on CurrentTime: CurrentTime only ticks on
      // the server's ~1 s ServerStatus update, whose cadence under CI load made this flake even with a
      // 20 s window. A client-driven write is deterministic — each write is its own change to deliver.
      if (nsIdx > 0) {
        const subNodeId = `ns=${nsIdx};s=Int32`;
        const sub = ClientSubscription.create(session, {
          requestedPublishingInterval: 200,
          requestedMaxKeepAliveCount: 10,
          requestedLifetimeCount: 100,
          maxNotificationsPerPublish: 10,
          publishingEnabled: true,
          priority: 1,
        });
        await new Promise((res, rej) => {
          sub.on("started", res);
          sub.on("internal_error", rej);
          setTimeout(() => rej(new Error("subscription start timeout")), 15000);
        }).catch((e) => check("Subscription started", false, e.message));

        const item = ClientMonitoredItem.create(
          sub,
          { nodeId: subNodeId, attributeId: AttributeIds.Value },
          { samplingInterval: 100, discardOldest: true, queueSize: 10 },
          TimestampsToReturn.Both,
        );
        // Wait until the item is monitoring server-side so the writes below are captured.
        await new Promise((res) => {
          item.on("initialized", res);
          setTimeout(res, 5000);
        });

        let changes = 0;
        const gotTwo = new Promise((res) => {
          item.on("changed", () => {
            if (++changes >= 2) res();
          });
        });
        // Write distinct values spaced beyond the sampling interval; each is a separate data change.
        // Fully await the writes (no write must outlive the session, or node-opcua throws once it is
        // closed below), then wait for the notifications to land — most arrive during the writes.
        for (let v = 1; v <= 5; v++) {
          await session.write({
            nodeId: subNodeId,
            attributeId: AttributeIds.Value,
            value: { value: { dataType: DataType.Int32, value: v } },
          });
          await new Promise((r) => setTimeout(r, 300));
        }
        await Promise.race([gotTwo, new Promise((r) => setTimeout(r, 3000))]);
        check("Subscription delivers data-change notifications", changes >= 2, `got ${changes}`);

        // SetTriggering interop: link a second monitored item to the first and confirm the service
        // round-trips with a Good result across the independent stack (server-side behaviour is
        // covered by the Rust triggering tests; this grounds the request/response interop).
        const linked = ClientMonitoredItem.create(
          sub,
          { nodeId: CURRENT_TIME, attributeId: AttributeIds.Value },
          { samplingInterval: 250, discardOldest: true, queueSize: 10 },
          TimestampsToReturn.Both,
        );
        await new Promise((res) => {
          linked.on("initialized", res);
          setTimeout(res, 5000);
        });
        const st = await session.setTriggering({
          subscriptionId: sub.subscriptionId,
          triggeringItemId: item.monitoredItemId,
          linksToAdd: [linked.monitoredItemId],
          linksToRemove: [],
        });
        const addResults = st.addResults || [];
        check(
          "SetTriggering links a monitored item (Good)",
          addResults.length === 1 && addResults[0].isGood(),
          `addResults=${addResults.map((s) => s.toString()).join(",")}`,
        );

        await sub.terminate();
      }
    },
  );
}

async function testSecuredSession() {
  console.log("\n[Basic256Sha256 / SignAndEncrypt] secured handshake + read");
  const ok = await withSession(
    "Secured",
    {
      securityMode: MessageSecurityMode.SignAndEncrypt,
      securityPolicy: SecurityPolicy.Basic256Sha256,
    },
    async (session) => {
      check("Secured session established", true);
      const dv = await session.read({ nodeId: CURRENT_TIME, attributeId: AttributeIds.Value });
      check("Secured read is Good", dv.statusCode.isGood(), dv.statusCode.toString());
    },
  );
  if (!ok) check("Secured read is Good", false, "session not established");
}

async function testSecurityPolicyMatrix() {
  console.log("\n[security matrix] connect + read across policies");
  const policies = [
    ["Basic256Sha256 / Sign", MessageSecurityMode.Sign, SecurityPolicy.Basic256Sha256],
    ["Basic256Sha256 / SignAndEncrypt", MessageSecurityMode.SignAndEncrypt, SecurityPolicy.Basic256Sha256],
    ["Aes128Sha256RsaOaep / SignAndEncrypt", MessageSecurityMode.SignAndEncrypt, SecurityPolicy.Aes128_Sha256_RsaOaep],
    ["Aes256Sha256RsaPss / SignAndEncrypt", MessageSecurityMode.SignAndEncrypt, SecurityPolicy.Aes256_Sha256_RsaPss],
  ];
  for (const [label, securityMode, securityPolicy] of policies) {
    let read = false;
    await withSession(label, { securityMode, securityPolicy }, async (session) => {
      const dv = await session.read({ nodeId: CURRENT_TIME, attributeId: AttributeIds.Value });
      read = dv.statusCode.isGood();
    });
    check(`${label}: connect + read`, read);
  }
}

async function testWriteAndTranslate() {
  console.log("\n[Basic256Sha256 / SignAndEncrypt] write / read-back + TranslateBrowsePath");
  await withSession("Write", SECURED, async (session) => {
    const nsArray = await session.readNamespaceArray();
    const nsIdx = nsArray.indexOf(DEMO_NS);

    // Write a value to a writable demo variable and read it back.
    if (nsIdx > 0) {
      const nodeId = `ns=${nsIdx};s=Int32`;
      const target = 1234567;
      const status = await session.write({
        nodeId,
        attributeId: AttributeIds.Value,
        value: { value: { dataType: DataType.Int32, value: target } },
      });
      check("Write to writable Int32 is Good", status.isGood(), status.toString());
      const dv = await session.read({ nodeId, attributeId: AttributeIds.Value });
      check("Read-back returns the written value", dv.value && dv.value.value === target, `got ${dv.value && dv.value.value}`);
    }

    // TranslateBrowsePathsToNodeIds: Server -> ServerStatus -> CurrentTime resolves to i=2258.
    const browsePath = makeBrowsePath(
      "RootFolder",
      "/Objects/Server.ServerStatus.CurrentTime",
    );
    const res = await session.translateBrowsePath(browsePath);
    check("TranslateBrowsePath is Good", res.statusCode.isGood(), res.statusCode.toString());
    const target = res.targets && res.targets[0] && res.targets[0].targetId;
    check(
      "TranslateBrowsePath resolves CurrentTime (i=2258)",
      target && target.toString() === "ns=0;i=2258",
      `got ${target && target.toString()}`,
    );
  });
}

async function testServiceBreadth() {
  console.log("\n[None] arrays / error paths / attributes / NoOp");
  await withSession(
    "Breadth",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      const nsArray = await session.readNamespaceArray();
      const nsIdx = nsArray.indexOf(DEMO_NS);

      // Array round-trip: write an Int32 array to a writable array variable and read it back.
      if (nsIdx > 0) {
        const nodeId = `ns=${nsIdx};s=Int32Array`;
        const arr = [11, 22, 33, 44];
        const status = await session.write({
          nodeId,
          attributeId: AttributeIds.Value,
          value: {
            value: { dataType: DataType.Int32, arrayType: VariantArrayType.Array, value: arr },
          },
        });
        check("Write Int32 array is Good", status.isGood(), status.toString());
        const dv = await session.read({ nodeId, attributeId: AttributeIds.Value });
        const got = dv.value && Array.from(dv.value.value || []);
        check(
          "Array read-back matches",
          got && got.length === arr.length && got.every((v, i) => v === arr[i]),
          `got ${JSON.stringify(got)}`,
        );
      }

      // Reading an unknown node returns Bad_NodeIdUnknown.
      const unknown = await session.read({
        nodeId: `ns=${nsIdx > 0 ? nsIdx : 1};s=NoSuchNode`,
        attributeId: AttributeIds.Value,
      });
      check(
        "Read unknown node -> BadNodeIdUnknown",
        unknown.statusCode.equals(StatusCodes.BadNodeIdUnknown),
        unknown.statusCode.toString(),
      );

      // Writing a read-only node (CurrentTime) is rejected.
      const roWrite = await session.write({
        nodeId: CURRENT_TIME,
        attributeId: AttributeIds.Value,
        value: { value: { dataType: DataType.DateTime, value: new Date() } },
      });
      check("Write to read-only CurrentTime is rejected", !roWrite.isGood(), roWrite.toString());

      // Read several attributes of the Server object in one request.
      const attrs = await session.read([
        { nodeId: "i=2253", attributeId: AttributeIds.NodeClass },
        { nodeId: "i=2253", attributeId: AttributeIds.BrowseName },
        { nodeId: "i=2253", attributeId: AttributeIds.DisplayName },
      ]);
      check(
        "Read Server NodeClass = Object",
        attrs[0].statusCode.isGood() && attrs[0].value.value === NodeClass.Object,
        `got ${attrs[0].value && attrs[0].value.value}`,
      );
      check(
        "Read Server BrowseName + DisplayName Good",
        attrs[1].statusCode.isGood() && attrs[2].statusCode.isGood(),
      );

      // Call the no-argument NoOp method.
      if (nsIdx > 0) {
        const noop = await session.call({
          objectId: `ns=${nsIdx};s=Functions`,
          methodId: `ns=${nsIdx};s=NoOp`,
          inputArguments: [],
        });
        check("NoOp method call is Good", noop.statusCode.isGood(), noop.statusCode.toString());
      }
    },
  );
}

function int64Eq(a, target) {
  if (Array.isArray(a)) return a[0] * 4294967296 + (a[1] >>> 0) === target;
  return Number(a) === target;
}

// Round-trip every primitive scalar type the demo exposes (ns;s=<TypeName>).
async function testScalarTypes() {
  console.log("\n[None] scalar type round-trips");
  const scalars = [
    ["Boolean", DataType.Boolean, true, (a, b) => a === b],
    ["Byte", DataType.Byte, 200, (a, b) => a === b],
    ["SByte", DataType.SByte, -50, (a, b) => a === b],
    ["Int16", DataType.Int16, -1234, (a, b) => a === b],
    ["UInt16", DataType.UInt16, 60000, (a, b) => a === b],
    ["Int32", DataType.Int32, -100000, (a, b) => a === b],
    ["UInt32", DataType.UInt32, 4000000000, (a, b) => a === b],
    ["Int64", DataType.Int64, 1234567890, (a, b) => int64Eq(a, b)],
    ["UInt64", DataType.UInt64, 9876543210, (a, b) => int64Eq(a, b)],
    ["Float", DataType.Float, 3.5, (a, b) => a === b],
    ["Double", DataType.Double, 2.71828, (a, b) => Math.abs(a - b) < 1e-9],
    ["String", DataType.String, "interop-string-✓", (a, b) => a === b],
    ["DateTime", DataType.DateTime, new Date(1700000000000),
      (a, b) => a instanceof Date && a.getTime() === b.getTime()],
    ["Guid", DataType.Guid, "72962B91-FA75-4AE6-8D28-B404DC7DAF63",
      (a, b) => String(a).toUpperCase() === String(b).toUpperCase()],
  ];
  await withSession(
    "Scalars",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      const nsArray = await session.readNamespaceArray();
      const ns = nsArray.indexOf(DEMO_NS);
      for (const [name, dataType, value, eq] of scalars) {
        const nodeId = `ns=${ns};s=${name}`;
        const status = await session.write({
          nodeId,
          attributeId: AttributeIds.Value,
          value: { value: { dataType, value } },
        });
        const dv = await session.read({ nodeId, attributeId: AttributeIds.Value });
        const got = dv.value && dv.value.value;
        check(
          `${name} write + read-back round-trips`,
          status.isGood() && dv.statusCode.isGood() && eq(got, value),
          `wrote ${JSON.stringify(value)} got ${JSON.stringify(got)} (${status.toString()})`,
        );
      }
    },
  );
}

// Breadth of the Read service: many attributes, a multi-node request, and timestamps.
async function testReadBreadth() {
  console.log("\n[None] read breadth: attributes / multi-node / timestamps");
  await withSession(
    "ReadBreadth",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      const nsArray = await session.readNamespaceArray();
      const ns = nsArray.indexOf(DEMO_NS);
      const v = `ns=${ns};s=Double`;

      // Read a spread of attributes of a Variable node in one request.
      const ids = [
        AttributeIds.NodeId,
        AttributeIds.NodeClass,
        AttributeIds.BrowseName,
        AttributeIds.DisplayName,
        AttributeIds.DataType,
        AttributeIds.ValueRank,
        AttributeIds.AccessLevel,
        AttributeIds.UserAccessLevel,
      ];
      const attrs = await session.read(ids.map((attributeId) => ({ nodeId: v, attributeId })));
      check(
        "Read 8 attributes of a Variable all Good",
        attrs.length === ids.length && attrs.every((a) => a.statusCode.isGood()),
        attrs.map((a) => a.statusCode.toString()).join(","),
      );
      check(
        "Variable NodeClass = Variable",
        attrs[1].value.value === NodeClass.Variable,
        `got ${attrs[1].value && attrs[1].value.value}`,
      );

      // Read multiple distinct nodes in one request.
      const multi = await session.read([
        { nodeId: CURRENT_TIME, attributeId: AttributeIds.Value },
        { nodeId: "i=2255", attributeId: AttributeIds.Value }, // NamespaceArray
        { nodeId: v, attributeId: AttributeIds.Value },
      ]);
      check(
        "Read of 3 distinct nodes all Good",
        multi.length === 3 && multi.every((d) => d.statusCode.isGood()),
      );

      // A value read carries source and server timestamps.
      const dv = await session.read({ nodeId: CURRENT_TIME, attributeId: AttributeIds.Value });
      check(
        "Read returns source + server timestamps",
        dv.sourceTimestamp instanceof Date && dv.serverTimestamp instanceof Date,
      );
    },
  );
}

// Browse variations: inverse direction and a NodeClass-filtered browse.
async function testBrowseBreadth() {
  console.log("\n[None] browse variations");
  await withSession(
    "BrowseBreadth",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      // Inverse browse from the Server object finds its parent (Objects folder).
      const inv = await session.browse({
        nodeId: "i=2253",
        browseDirection: BrowseDirection.Inverse,
        resultMask: 63,
      });
      check(
        "Inverse browse of Server returns a parent reference",
        inv.statusCode.isGood() && inv.references && inv.references.length > 0,
        inv.statusCode.toString(),
      );

      // Forward browse filtered to Object nodes only.
      const objs = await session.browse({
        nodeId: "i=85",
        browseDirection: BrowseDirection.Forward,
        nodeClassMask: 1, // Object
        resultMask: 63,
      });
      check(
        "NodeClass-filtered browse returns only Objects",
        objs.statusCode.isGood() &&
          objs.references &&
          objs.references.length > 0 &&
          objs.references.every((r) => r.nodeClass === NodeClass.Object),
      );
    },
  );
}

// Services the demo does not implement must fail cleanly rather than hang or misreport.
async function testUnsupportedServices() {
  console.log("\n[None] unsupported services fail cleanly");
  await withSession(
    "Unsupported",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      // HistoryRead on a non-historizing server returns a Bad status, not Good.
      try {
        const start = new Date(Date.now() - 60000);
        const end = new Date();
        const r = await session.readHistoryValue(CURRENT_TIME, start, end);
        const sc = Array.isArray(r) ? r[0] && r[0].statusCode : r.statusCode;
        check(
          "HistoryRead on non-historizing node is rejected",
          sc && !sc.isGood(),
          sc ? sc.toString() : "no status",
        );
      } catch (e) {
        // A thrown service fault is also an acceptable rejection.
        check("HistoryRead on non-historizing node is rejected", true, e.message);
      }

      // HistoryRead on the demo's seeded historizing variable returns real values.
      const nsArray = await session.readNamespaceArray();
      const nsIdx = nsArray.indexOf(DEMO_NS);
      if (nsIdx > 0) {
        const histNode = `ns=${nsIdx};s=HistoricalDouble`;
        const start = new Date(Date.now() - 5 * 60 * 1000);
        const end = new Date(Date.now() + 60 * 1000);
        try {
          const r = await session.readHistoryValue(histNode, start, end);
          const res = Array.isArray(r) ? r[0] : r;
          const values =
            (res && res.historyData && res.historyData.dataValues) || [];
          const sc = res && res.statusCode;
          check(
            "HistoryRead on a historizing node returns values",
            (!sc || sc.isGood()) && values.length > 0,
            `status=${sc ? sc.toString() : "?"} count=${values.length}`,
          );
        } catch (e) {
          check("HistoryRead on a historizing node returns values", false, e.message);
        }
      }
    },
  );
}

// Failure modes: the server must reject bad requests with the right status codes.
async function testFailureModes() {
  console.log("\n[None] failure modes / error status codes");

  // A wrong password is rejected (we test the success path separately).
  {
    const client = newClient(SECURED);
    try {
      await client.connect(endpoint);
      await client.createSession({
        type: UserTokenType.UserName,
        userName: "sample1",
        password: "wrong-password",
      });
      check("Wrong password is rejected", false, "session unexpectedly created");
      await client.disconnect();
    } catch (e) {
      check(
        "Wrong password is rejected",
        /BadUserAccessDenied|BadIdentityTokenRejected|rejected|denied/i.test(e.message),
        e.message,
      );
      try {
        await client.disconnect();
      } catch {
        /* ignore */
      }
    }
  }

  // An unknown user is rejected.
  {
    const client = newClient(SECURED);
    try {
      await client.connect(endpoint);
      await client.createSession({
        type: UserTokenType.UserName,
        userName: "no-such-user",
        password: "whatever",
      });
      check("Unknown user is rejected", false, "session unexpectedly created");
      await client.disconnect();
    } catch (e) {
      check(
        "Unknown user is rejected",
        /BadUserAccessDenied|BadIdentityTokenRejected|rejected|denied/i.test(e.message),
        e.message,
      );
      try {
        await client.disconnect();
      } catch {
        /* ignore */
      }
    }
  }

  await withSession(
    "Failures",
    { securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None },
    async (session) => {
      const ns = (await session.readNamespaceArray()).indexOf(DEMO_NS);

      // Writing the wrong data type to a typed variable is rejected.
      const wt = await session.write({
        nodeId: `ns=${ns};s=Int32`,
        attributeId: AttributeIds.Value,
        value: { value: { dataType: DataType.String, value: "not-an-int" } },
      });
      check("Wrong-type write is rejected", !wt.isGood(), wt.toString());

      // Calling a non-existent method is rejected.
      const um = await session.call({
        objectId: `ns=${ns};s=Functions`,
        methodId: `ns=${ns};s=NoSuchMethod`,
        inputArguments: [],
      });
      check("Call of unknown method is rejected", !um.statusCode.isGood(), um.statusCode.toString());

      // Browsing with a referenceTypeId that is not a ReferenceType must return
      // Bad_ReferenceTypeIdInvalid — an independent-client check of the server's P4-VIEW-01 fix.
      const bad = await session.browse({
        nodeId: "i=85",
        referenceTypeId: "i=2253", // the Server object — an Object, not a ReferenceType
        browseDirection: BrowseDirection.Forward,
        includeSubtypes: false,
        resultMask: 63,
      });
      check(
        "Browse with a non-ReferenceType referenceTypeId -> BadReferenceTypeIdInvalid",
        bad.statusCode.equals(StatusCodes.BadReferenceTypeIdInvalid),
        bad.statusCode.toString(),
      );

      // Reading an invalid attribute id is rejected.
      const ia = await session.read({ nodeId: CURRENT_TIME, attributeId: 999 });
      check(
        "Read of an invalid attribute id -> BadAttributeIdInvalid",
        ia.statusCode.equals(StatusCodes.BadAttributeIdInvalid),
        ia.statusCode.toString(),
      );

      // Calling a zero-argument method with an argument is rejected.
      const wa = await session.call({
        objectId: `ns=${ns};s=Functions`,
        methodId: `ns=${ns};s=NoOp`,
        inputArguments: [{ dataType: DataType.Int32, value: 1 }],
      });
      check("Method call with wrong arguments is rejected", !wa.statusCode.isGood(), wa.statusCode.toString());

      // A browse path that resolves to nothing returns Bad_NoMatch.
      const nm = await session.translateBrowsePath(
        makeBrowsePath("RootFolder", "/Objects/NoSuchChildXYZ"),
      );
      check(
        "TranslateBrowsePath with no match -> BadNoMatch",
        nm.statusCode.equals(StatusCodes.BadNoMatch),
        nm.statusCode.toString(),
      );

      // BrowseNext with an invalid continuation point is rejected.
      const bn = await session.browseNext(Buffer.from([1, 2, 3, 4]), false);
      const bnsc = Array.isArray(bn) ? bn[0].statusCode : bn.statusCode;
      check(
        "BrowseNext with an invalid continuation point -> BadContinuationPointInvalid",
        bnsc.equals(StatusCodes.BadContinuationPointInvalid),
        bnsc.toString(),
      );

      // --- Independent confirmation of this session's server-side fixes (#82/#83/#84). ---

      // Calling a method with fewer arguments than it declares returns Bad_ArgumentsMissing.
      // Add declares two Int64 inputs; we supply one.
      const am = await session.call({
        objectId: `ns=${ns};s=Functions`,
        methodId: `ns=${ns};s=Add`,
        inputArguments: [{ dataType: DataType.Int64, value: 1 }],
      });
      check(
        "Method call with missing arguments -> BadArgumentsMissing",
        am.statusCode.equals(StatusCodes.BadArgumentsMissing),
        am.statusCode.toString(),
      );

      // Writing a scalar to an array node (ValueRank mismatch) returns Bad_TypeMismatch.
      const vr = await session.write({
        nodeId: `ns=${ns};s=Int32Array`,
        attributeId: AttributeIds.Value,
        value: {
          value: { dataType: DataType.Int32, arrayType: VariantArrayType.Scalar, value: 5 },
        },
      });
      check(
        "Scalar written to an array node -> BadTypeMismatch",
        vr.equals(StatusCodes.BadTypeMismatch),
        vr.toString(),
      );

      // Creating a monitored item on a non-existent node returns Bad_NodeIdUnknown.
      const sub = ClientSubscription.create(session, {
        requestedPublishingInterval: 200,
        requestedLifetimeCount: 100,
        requestedMaxKeepAliveCount: 10,
        maxNotificationsPerPublish: 100,
        publishingEnabled: true,
        priority: 1,
      });
      await new Promise((res) => sub.on("started", res));
      const mi = await session.createMonitoredItems({
        subscriptionId: sub.subscriptionId,
        timestampsToReturn: TimestampsToReturn.Both,
        itemsToCreate: [
          {
            itemToMonitor: { nodeId: `ns=${ns};s=NoSuchNodeXYZ`, attributeId: AttributeIds.Value },
            monitoringMode: MonitoringMode.Reporting,
            requestedParameters: {
              clientHandle: 1,
              samplingInterval: 200,
              queueSize: 10,
              discardOldest: true,
            },
          },
        ],
      });
      const misc = mi.results[0].statusCode;
      check(
        "Monitored item on unknown node -> BadNodeIdUnknown",
        misc.equals(StatusCodes.BadNodeIdUnknown),
        misc.toString(),
      );
      await sub.terminate();

      // Part 8 percent-deadband validation: PercentDeadband requires an EURange property.
      const daSub = ClientSubscription.create(session, {
        requestedPublishingInterval: 200,
        requestedLifetimeCount: 100,
        requestedMaxKeepAliveCount: 10,
        maxNotificationsPerPublish: 100,
        publishingEnabled: true,
        priority: 1,
      });
      await new Promise((res) => daSub.on("started", res));
      const percentFilter = new DataChangeFilter({
        trigger: DataChangeTrigger.StatusValue,
        deadbandType: DeadbandType.Percent,
        deadbandValue: 10,
      });
      const monitoringParameters = (clientHandle, filter = null) => ({
        clientHandle,
        samplingInterval: 100,
        queueSize: 1,
        discardOldest: true,
        filter,
      });
      const dataChangeItem = (nodeId, clientHandle, filter = null) => ({
        itemToMonitor: { nodeId, attributeId: AttributeIds.Value },
        monitoringMode: MonitoringMode.Reporting,
        requestedParameters: monitoringParameters(clientHandle, filter),
      });

      const da = await session.createMonitoredItems({
        subscriptionId: daSub.subscriptionId,
        timestampsToReturn: TimestampsToReturn.Both,
        itemsToCreate: [
          dataChangeItem(`ns=${ns};s=PercentDeadbandAnalog`, 2001, percentFilter),
          dataChangeItem(`ns=${ns};s=PercentDeadbandPlain`, 2002),
        ],
      });
      check(
        "CreateMonitoredItems PercentDeadband with EURange is Good",
        da.results[0].statusCode.equals(StatusCodes.Good),
        da.results[0].statusCode.toString(),
      );
      check(
        "CreateMonitoredItems plain DataAccess node is Good",
        da.results[1].statusCode.equals(StatusCodes.Good),
        da.results[1].statusCode.toString(),
      );

      const dm = await session.modifyMonitoredItems({
        subscriptionId: daSub.subscriptionId,
        timestampsToReturn: TimestampsToReturn.Both,
        itemsToModify: [
          {
            monitoredItemId: da.results[1].monitoredItemId,
            requestedParameters: monitoringParameters(2003, percentFilter),
          },
        ],
      });
      check(
        "ModifyMonitoredItems PercentDeadband without EURange -> BadDeadbandFilterInvalid",
        dm.results[0].statusCode.equals(StatusCodes.BadDeadbandFilterInvalid),
        dm.results[0].statusCode.toString(),
      );

      await expectServiceFault(
        "CreateMonitoredItems over subscription limit -> BadTooManyMonitoredItems",
        () =>
          session.createMonitoredItems({
            subscriptionId: daSub.subscriptionId,
            timestampsToReturn: TimestampsToReturn.Both,
            itemsToCreate: Array.from({ length: 9 }, (_, i) =>
              dataChangeItem(`ns=${ns};s=Int32`, 2100 + i),
            ),
          }),
        StatusCodes.BadTooManyMonitoredItems,
      );
      await daSub.terminate();

      await expectServiceFault(
        "Publish with no subscriptions -> BadNoSubscription",
        () => session.publish(new PublishRequest({ subscriptionAcknowledgements: [] })),
        StatusCodes.BadNoSubscription,
      );

      await expectServiceFault(
        "HistoryRead with TimestampsToReturn.Neither -> BadTimestampsToReturnInvalid",
        () =>
          session.historyRead(
            new HistoryReadRequest({
              historyReadDetails: new ReadRawModifiedDetails({
                isReadModified: false,
                startTime: new Date(Date.now() - 5 * 60 * 1000),
                endTime: new Date(Date.now() + 60 * 1000),
                numValuesPerNode: 100,
                returnBounds: false,
              }),
              timestampsToReturn: TimestampsToReturn.Neither,
              releaseContinuationPoints: false,
              nodesToRead: [{ nodeId: `ns=${ns};s=HistoricalDouble` }],
            }),
          ),
        StatusCodes.BadTimestampsToReturnInvalid,
      );
    },
  );
}

// A server that does not auto-trust client certs must reject an unknown ("discarded")
// client certificate on a secured handshake.
async function testUntrustedCert() {
  if (!NOTRUST_ENDPOINT) return;
  console.log("\n[no-trust server] discarded / untrusted client certificate");
  const client = newClient(SECURED);
  try {
    await client.connect(NOTRUST_ENDPOINT);
    const s = await client.createSession();
    check("Untrusted client cert is rejected by the no-trust server", false, "connected unexpectedly");
    await s.close();
    await client.disconnect();
  } catch (e) {
    check(
      "Untrusted client cert is rejected by the no-trust server",
      /BadSecurityChecksFailed|BadCertificate|untrusted|rejected|not.*trust/i.test(e.message),
      e.message,
    );
    try {
      await client.disconnect();
    } catch {
      /* ignore */
    }
  }
}

async function testUsernamePassword() {
  console.log("\n[Basic256Sha256 / SignAndEncrypt] username/password identity token");
  const ok = await withSession(
    "UserName",
    SECURED,
    async (session) => {
      check("Username/password session established", true);
      const dv = await session.read({ nodeId: CURRENT_TIME, attributeId: AttributeIds.Value });
      check("Authenticated read is Good", dv.statusCode.isGood(), dv.statusCode.toString());
    },
    { type: UserTokenType.UserName, userName: "sample1", password: "sample1_password" },
  );
  if (!ok) check("Authenticated read is Good", false, "session not established");
}

async function main() {
  console.log(`async-opcua interop smoke test against ${endpoint}`);
  await setupClientCertificate();
  await testDiscovery();
  await testUnsecuredServices();
  await testSecuredSession();
  await testSecurityPolicyMatrix();
  await testWriteAndTranslate();
  await testServiceBreadth();
  await testScalarTypes();
  await testReadBreadth();
  await testBrowseBreadth();
  await testUnsupportedServices();
  await testFailureModes();
  await testUntrustedCert();
  await testUsernamePassword();
  console.log(
    `\n${failures === 0 ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m"}: ${checks - failures}/${checks} checks passed`,
  );
  process.exit(failures);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
