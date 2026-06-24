// Independent node-opcua interop checks for subscription state-machine edges.
//
// Usage:
//   cd samples/demo-server/interop
//   node ../../../specs/multi-ai-test-suites/codex/node_opcua_subscription_edges.mjs opc.tcp://localhost:4855/
//
// This script assumes a demo server is already running. It does not launch a
// server and does not bind a listening port.

import {
  AttributeIds,
  ClientMonitoredItem,
  ClientSubscription,
  MessageSecurityMode,
  MonitoringMode,
  OPCUAClient,
  SecurityPolicy,
  TimestampsToReturn,
} from "node-opcua";

const endpoint = process.argv[2] || "opc.tcp://localhost:4855/";
const CURRENT_TIME = "i=2258";

let failures = 0;
let checks = 0;

function check(name, condition, detail = "") {
  checks += 1;
  if (condition) {
    console.log(`ok   ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}${detail ? ` - ${detail}` : ""}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const client = OPCUAClient.create({
    endpointMustExist: false,
    securityMode: MessageSecurityMode.None,
    securityPolicy: SecurityPolicy.None,
    connectionStrategy: { maxRetry: 1, initialDelay: 200, maxDelay: 500 },
  });

  await client.connect(endpoint);
  const session = await client.createSession();

  try {
    const sub = ClientSubscription.create(session, {
      requestedPublishingInterval: 100,
      requestedMaxKeepAliveCount: 4,
      requestedLifetimeCount: 60,
      maxNotificationsPerPublish: 10,
      publishingEnabled: true,
      priority: 0,
    });

    await new Promise((resolve, reject) => {
      sub.once("started", resolve);
      sub.once("internal_error", reject);
      setTimeout(() => reject(new Error("subscription start timeout")), 5000);
    });

    const item = ClientMonitoredItem.create(
      sub,
      { nodeId: CURRENT_TIME, attributeId: AttributeIds.Value },
      {
        samplingInterval: 100,
        discardOldest: true,
        queueSize: 5,
        monitoringMode: MonitoringMode.Reporting,
      },
      TimestampsToReturn.Both,
    );

    let changes = 0;
    item.on("changed", () => {
      changes += 1;
    });

    await sleep(1500);
    check("Reporting mode produces data changes", changes > 0, `changes=${changes}`);

    changes = 0;
    await item.setMonitoringMode(MonitoringMode.Disabled);
    await sleep(1200);
    check("Disabled monitoring mode suppresses data changes", changes === 0, `changes=${changes}`);

    await item.setMonitoringMode(MonitoringMode.Reporting);
    await sleep(1500);
    check("Reporting mode resumes data changes after Disabled", changes > 0, `changes=${changes}`);

    await sub.terminate();
  } finally {
    await session.close();
    await client.disconnect();
  }

  console.log(`checks=${checks} failures=${failures}`);
  process.exitCode = failures;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

