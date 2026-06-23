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
  ClientSubscription,
  ClientMonitoredItem,
} from "node-opcua";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdirSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const endpoint = process.argv[2] || "opc.tcp://localhost:4855/";

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

async function withSession(label, opts, fn) {
  const client = newClient(opts);
  try {
    await client.connect(endpoint);
    const session = await client.createSession();
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

      // Subscribe to CurrentTime and require at least two data changes.
      const sub = ClientSubscription.create(session, {
        requestedPublishingInterval: 250,
        requestedMaxKeepAliveCount: 10,
        requestedLifetimeCount: 100,
        maxNotificationsPerPublish: 10,
        publishingEnabled: true,
        priority: 1,
      });
      await new Promise((res, rej) => {
        sub.on("started", res);
        sub.on("internal_error", rej);
        setTimeout(() => rej(new Error("subscription start timeout")), 5000);
      }).catch((e) => check("Subscription started", false, e.message));

      const changes = await new Promise((res) => {
        let n = 0;
        const item = ClientMonitoredItem.create(
          sub,
          { nodeId: CURRENT_TIME, attributeId: AttributeIds.Value },
          { samplingInterval: 250, discardOldest: true, queueSize: 10 },
          TimestampsToReturn.Both,
        );
        item.on("changed", () => {
          if (++n >= 2) res(n);
        });
        setTimeout(() => res(n), 4000);
      });
      check("Subscription delivers data-change notifications", changes >= 2, `got ${changes}`);
      await sub.terminate();
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

async function main() {
  console.log(`async-opcua interop smoke test against ${endpoint}`);
  await setupClientCertificate();
  await testDiscovery();
  await testUnsecuredServices();
  await testSecuredSession();
  console.log(
    `\n${failures === 0 ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m"}: ${checks - failures}/${checks} checks passed`,
  );
  process.exit(failures);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
