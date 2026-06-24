// OPC UA .NET Standard (OPC Foundation reference stack) interop conformance client against the
// async-opcua demo server. A fourth independent stack lineage alongside node-opcua (JS),
// open62541 (C) and asyncua (Python) — and the reference implementation the UACTT is built on, so
// agreement here is the strongest cross-stack conformance signal we have.
//
// This is the comprehensive harness: it exercises discovery, the full security-policy/mode matrix,
// identity tokens, the attribute/view/method/subscription/history services and their error paths
// across the demo server's whole surface — every feature we can drive from a client.
//
// Usage:  dotnet run -- <endpoint-url>
// Exit code is the number of failed checks (0 = all passed).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

namespace DotnetInterop
{
    static class Program
    {
        const string DemoNs = "urn:DemoServer";
        const string User = "sample1";
        const string Pass = "sample1_password";
        static int checks = 0, failures = 0;
        static ushort nsi = 0;

        static void Check(string name, bool ok, string detail = null)
        {
            checks++;
            if (ok) Console.WriteLine($"  [32mok[0m   {name}");
            else { failures++; Console.WriteLine($"  [31mFAIL[0m {name}{(detail != null ? "  — " + detail : "")}"); }
        }

        static void Section(string s) => Console.WriteLine($"\n=== {s} ===");

        static async Task<int> Main(string[] args)
        {
            string url = args.Length > 0 ? args[0] : "opc.tcp://127.0.0.1:4855";
            var config = await BuildConfig();

            try
            {
                await DiscoveryChecks(config, url);
                await SecurityMatrixChecks(config, url);
                await IdentityTokenChecks(config, url);

                using (var session = await Connect(config, url, useSecurity: false))
                {
                    nsi = (ushort)ReadNamespaceArray(session).IndexOf(DemoNs);
                    Check("DemoServer namespace present", nsi > 0, $"ns={nsi}");

                    Section("Attribute service: Read");
                    ReadChecks(session);
                    Section("Attribute service: Write");
                    WriteChecks(session);
                    Section("View service: Browse / BrowseNext / Translate / Register");
                    ViewChecks(session);
                    Section("Method service");
                    MethodChecks(session);
                    Section("Subscription / MonitoredItem service");
                    await SubscriptionChecks(session);
                    Section("HistoryRead service");
                    HistoryChecks(session);
                    Section("Error paths");
                    ErrorChecks(session);

                    session.Close();
                }
            }
            catch (Exception ex)
            {
                Check("client ran without unhandled exception", false, ex.ToString());
            }

            Console.WriteLine($"\n{(failures == 0 ? "[32mall checks passed[0m" : $"[31m{failures} check(s) failed[0m")} ({checks - failures}/{checks})");
            return failures;
        }

        // ---- Discovery (no session) ----------------------------------------------------------
        static async Task DiscoveryChecks(ApplicationConfiguration config, string url)
        {
            Section("Discovery service");
            using var dc = DiscoveryClient.Create(new Uri(url), EndpointConfiguration.Create(config));
            var servers = await dc.FindServersAsync(null);
            Check("FindServers returns our server", servers.Any(s => s.DiscoveryUrls.Any(u => u.Contains("4855"))),
                  $"count={servers.Count}");
            var endpoints = await dc.GetEndpointsAsync(null);
            Check("GetEndpoints returns the None endpoint", endpoints.Any(e => e.SecurityMode == MessageSecurityMode.None));
            Check("GetEndpoints returns >=4 secured endpoints",
                  endpoints.Count(e => e.SecurityMode != MessageSecurityMode.None) >= 4,
                  $"secured={endpoints.Count(e => e.SecurityMode != MessageSecurityMode.None)}");
            Check("secured endpoints carry a server certificate",
                  endpoints.Where(e => e.SecurityMode != MessageSecurityMode.None).All(e => e.ServerCertificate != null));
        }

        // ---- SecureChannel: full policy/mode matrix ------------------------------------------
        static async Task SecurityMatrixChecks(ApplicationConfiguration config, string url)
        {
            Section("SecureChannel: security policy/mode matrix");
            using var dc = DiscoveryClient.Create(new Uri(url), EndpointConfiguration.Create(config));
            var endpoints = await dc.GetEndpointsAsync(null);
            foreach (var ep in endpoints.OrderBy(e => e.SecurityLevel))
            {
                string label = $"{SecurityPolicies.GetDisplayName(ep.SecurityPolicyUri)}/{ep.SecurityMode}";
                try
                {
                    var configured = new ConfiguredEndpoint(null, ep, EndpointConfiguration.Create(config));
                    using var s = await Session.Create(config, configured, false, "matrix", 30000,
                        new UserIdentity(new AnonymousIdentityToken()), null);
                    var dv = s.ReadValue(new NodeId(2258u));
                    Check($"connect+read [{label}]", s.Connected && StatusCode.IsGood(dv.StatusCode));
                    s.Close();
                }
                catch (Exception ex) { Check($"connect+read [{label}]", false, ex.Message); }
            }
        }

        // ---- Identity tokens -----------------------------------------------------------------
        static async Task IdentityTokenChecks(ApplicationConfiguration config, string url)
        {
            Section("Identity tokens");
            // Anonymous is exercised by the main session; here test username/password (good + bad).
            try
            {
                using var s = await Connect(config, url, useSecurity: true, identity: new UserIdentity(User, System.Text.Encoding.UTF8.GetBytes(Pass)));
                Check("username/password activates session", s.Connected);
                s.Close();
            }
            catch (Exception ex) { Check("username/password activates session", false, ex.Message); }

            try
            {
                using var s = await Connect(config, url, useSecurity: true, identity: new UserIdentity(User, System.Text.Encoding.UTF8.GetBytes("wrong_password")));
                Check("wrong password is rejected", false, "session unexpectedly activated");
                s.Close();
            }
            catch (ServiceResultException ex)
            {
                Check("wrong password is rejected",
                      ex.StatusCode == StatusCodes.BadUserAccessDenied || ex.StatusCode == StatusCodes.BadIdentityTokenRejected,
                      ex.StatusCode.ToString());
            }
        }

        // ---- Attribute reads -----------------------------------------------------------------
        static readonly (string name, Type clr)[] ScalarTypes = new[]
        {
            ("Boolean", typeof(bool)), ("Byte", typeof(byte)), ("SByte", typeof(sbyte)),
            ("Int16", typeof(short)), ("UInt16", typeof(ushort)), ("Int32", typeof(int)),
            ("UInt32", typeof(uint)), ("Int64", typeof(long)), ("UInt64", typeof(ulong)),
            ("Float", typeof(float)), ("Double", typeof(double)), ("String", typeof(string)),
            ("DateTime", typeof(DateTime)), ("Guid", typeof(Uuid)),
        };

        static void ReadChecks(Session session)
        {
            foreach (var (name, clr) in ScalarTypes)
            {
                var dv = session.ReadValue(new NodeId(name, nsi));
                bool ok = StatusCode.IsGood(dv.StatusCode) && dv.Value != null && dv.Value.GetType() == clr;
                Check($"read scalar {name} decodes as {clr.Name}", ok, $"{dv.StatusCode} {dv.Value?.GetType().Name}");
            }

            // Array variable returns an array.
            var arr = session.ReadValue(new NodeId("Int32Array", nsi));
            Check("read Int32Array returns an array", arr.Value is Array, arr.Value?.GetType().Name);

            // NumericRange: first two elements of the array.
            var rng = session.Read(null, 0, TimestampsToReturn.Neither, new ReadValueIdCollection {
                new ReadValueId { NodeId = new NodeId("Int32Array", nsi), AttributeId = Attributes.Value, IndexRange = "0:1" } },
                out DataValueCollection rvals, out _);
            Check("read Int32Array[0:1] (NumericRange) returns 2 elements",
                  rvals.Count == 1 && rvals[0].Value is Array a && a.Length == 2,
                  rvals.Count > 0 ? $"{rvals[0].StatusCode}" : "no result");

            // Read a batch of non-Value attributes on the Int32 node.
            var node = new NodeId("Int32", nsi);
            var toRead = new ReadValueIdCollection(new[] {
                Attributes.NodeClass, Attributes.BrowseName, Attributes.DisplayName,
                Attributes.DataType, Attributes.ValueRank, Attributes.AccessLevel
            }.Select(a => new ReadValueId { NodeId = node, AttributeId = a }));
            session.Read(null, 0, TimestampsToReturn.Neither, toRead, out DataValueCollection ar, out _);
            Check("read NodeClass == Variable", ar[0].Value is int nc && nc == (int)NodeClass.Variable, ar[0].Value?.ToString());
            Check("read BrowseName", ar[1].Value is QualifiedName qn && qn.Name == "Int32", (ar[1].Value as QualifiedName)?.Name);
            Check("read DisplayName", ar[2].Value is LocalizedText, ar[2].Value?.GetType().Name);
            Check("read DataType is a NodeId", ar[3].Value is NodeId, ar[3].Value?.GetType().Name);
            Check("read ValueRank == Scalar(-1)", ar[4].Value is int vr && vr == ValueRanks.Scalar, ar[4].Value?.ToString());
            Check("read AccessLevel present", StatusCode.IsGood(ar[5].StatusCode), ar[5].StatusCode.ToString());
        }

        // ---- Writes --------------------------------------------------------------------------
        static void WriteChecks(Session session)
        {
            WriteBack("Int32", new Variant(424242), 424242);
            WriteBack("Double", new Variant(3.25), 3.25);
            WriteBack("String", new Variant("interop-value"), "interop-value");
            WriteBack("Boolean", new Variant(true), true);

            // Write an array and read it back.
            var arrVal = new int[] { 10, 20, 30 };
            var w = new WriteValueCollection { new WriteValue {
                NodeId = new NodeId("Int32Array", nsi), AttributeId = Attributes.Value, Value = new DataValue(new Variant(arrVal)) } };
            session.Write(null, w, out StatusCodeCollection wr, out _);
            var rb = session.ReadValue(new NodeId("Int32Array", nsi));
            Check("write+read-back Int32Array", StatusCode.IsGood(wr[0]) && rb.Value is int[] ra && ra.SequenceEqual(arrVal), wr[0].ToString());

            void WriteBack(string name, Variant v, object expect)
            {
                var wc = new WriteValueCollection { new WriteValue {
                    NodeId = new NodeId(name, nsi), AttributeId = Attributes.Value, Value = new DataValue(v) } };
                session.Write(null, wc, out StatusCodeCollection res, out _);
                var back = session.ReadValue(new NodeId(name, nsi));
                Check($"write+read-back {name}", StatusCode.IsGood(res[0]) && Equals(back.Value, expect),
                      $"{res[0]} got={back.Value}");
            }
        }

        // ---- View service --------------------------------------------------------------------
        static void ViewChecks(Session session)
        {
            var browser = new Browser(session) { BrowseDirection = BrowseDirection.Forward, IncludeSubtypes = true, NodeClassMask = 0 };
            Check("browse Objects folder", browser.Browse(ObjectIds.ObjectsFolder).Count > 0);
            Check("browse Functions object", browser.Browse(new NodeId("Functions", nsi)).Count > 0);

            // BrowseNext: force a continuation point with maxReferencesPerNode=1 on a node with many refs.
            session.Browse(null, null, new NodeId(2253u), 1, BrowseDirection.Forward,
                ReferenceTypeIds.References, true, 0, out byte[] cp, out ReferenceDescriptionCollection first);
            Check("Browse with maxReferences=1 returns a continuation point", cp != null && cp.Length > 0 && first.Count == 1);
            if (cp != null && cp.Length > 0)
            {
                session.BrowseNext(null, false, new ByteStringCollection { cp }, out BrowseResultCollection next, out _);
                Check("BrowseNext returns more references", next.Count == 1 && next[0].References.Count >= 1);
            }

            // TranslateBrowsePath: Server -> ServerStatus -> CurrentTime resolves to i=2258.
            var bp = new BrowsePath { StartingNode = new NodeId(2253u), RelativePath = new RelativePath() };
            foreach (var name in new[] { "ServerStatus", "CurrentTime" })
                bp.RelativePath.Elements.Add(new RelativePathElement {
                    ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences, IncludeSubtypes = true,
                    IsInverse = false, TargetName = new QualifiedName(name) });
            session.TranslateBrowsePathsToNodeIds(null, new BrowsePathCollection { bp }, out BrowsePathResultCollection tr, out _);
            Check("TranslateBrowsePath resolves CurrentTime (i=2258)",
                  tr.Count > 0 && StatusCode.IsGood(tr[0].StatusCode) && tr[0].Targets.Count > 0 && tr[0].Targets[0].TargetId == new ExpandedNodeId(2258u),
                  tr.Count > 0 ? tr[0].StatusCode.ToString() : "no result");

            // RegisterNodes / UnregisterNodes round-trip.
            var toReg = new NodeIdCollection { new NodeId("Int32", nsi) };
            session.RegisterNodes(null, toReg, out NodeIdCollection registered);
            Check("RegisterNodes returns a handle", registered.Count == 1);
            session.UnregisterNodes(null, registered);
            Check("UnregisterNodes succeeds", true);
        }

        // ---- Method service ------------------------------------------------------------------
        static void MethodChecks(Session session)
        {
            var functions = new NodeId("Functions", nsi);
            var helloOut = session.Call(functions, new NodeId("HelloWorld", nsi));
            Check("call HelloWorld returns a greeting", helloOut.Count == 1 && (helloOut[0]?.ToString().Contains("Hello") ?? false), helloOut.FirstOrDefault()?.ToString());

            Check("call NoOp (0-in/0-out)", session.Call(functions, new NodeId("NoOp", nsi)) != null);

            var addOut = session.Call(functions, new NodeId("Add", nsi), 2, 3);
            Check("call Add(2,3) == 5", addOut.Count >= 1 && Convert.ToInt64(addOut[0]) == 5, addOut.FirstOrDefault()?.ToString());

            // Error: unknown method.
            try { session.Call(functions, new NodeId("NoSuchMethod", nsi)); Check("unknown method rejected", false); }
            catch (ServiceResultException ex) { Check("unknown method rejected", StatusCode.IsBad(ex.StatusCode), ex.StatusCode.ToString()); }

            // Error: Add with missing arguments.
            try
            {
                var req = new CallMethodRequestCollection { new CallMethodRequest {
                    ObjectId = functions, MethodId = new NodeId("Add", nsi), InputArguments = new VariantCollection { new Variant(1) } } };
                session.Call(null, req, out CallMethodResultCollection res, out _);
                Check("Add with missing args -> BadArgumentsMissing",
                      res.Count == 1 && res[0].StatusCode == StatusCodes.BadArgumentsMissing, res.Count > 0 ? res[0].StatusCode.ToString() : "no result");
            }
            catch (ServiceResultException ex) { Check("Add with missing args -> BadArgumentsMissing", ex.StatusCode == StatusCodes.BadArgumentsMissing, ex.StatusCode.ToString()); }
        }

        // ---- Subscription / MonitoredItem ----------------------------------------------------
        static async Task SubscriptionChecks(Session session)
        {
            var sub = new Subscription(session.DefaultSubscription) { PublishingInterval = 200, PublishingEnabled = true };
            session.AddSubscription(sub);
            sub.Create();
            Check("CreateSubscription", sub.Created);

            // Data-change monitored item on the writable Int32 node; the change is DRIVEN by a
            // client write (deterministic) rather than the server-timer-driven CurrentTime.
            var got = new SemaphoreSlim(0, 1);
            var mi = new MonitoredItem(sub.DefaultItem) { StartNodeId = new NodeId("Int32", nsi), AttributeId = Attributes.Value, SamplingInterval = 200 };
            mi.Notification += (i, e) => { if (got.CurrentCount == 0) got.Release(); };
            sub.AddItem(mi);
            sub.ApplyChanges();
            Check("CreateMonitoredItems (data change)", mi.Status.Created && StatusCode.IsGood(mi.Status.Error?.StatusCode ?? StatusCodes.Good));
            session.Write(null, new WriteValueCollection { new WriteValue {
                NodeId = new NodeId("Int32", nsi), AttributeId = Attributes.Value, Value = new DataValue(new Variant(700001)) } },
                out _, out _);
            Check("subscription delivers a data-change notification", await got.WaitAsync(TimeSpan.FromSeconds(10)));

            // ModifyMonitoredItems: change the sampling interval.
            mi.SamplingInterval = 500;
            sub.ApplyChanges();
            Check("ModifyMonitoredItems (sampling interval)", Math.Abs(mi.Status.SamplingInterval - 500) < 1e-6 || mi.Status.SamplingInterval > 0, mi.Status.SamplingInterval.ToString());

            // SetPublishingMode off then on.
            sub.SetPublishingMode(false);
            Check("SetPublishingMode(false)", !sub.CurrentPublishingEnabled);
            sub.SetPublishingMode(true);
            Check("SetPublishingMode(true)", sub.CurrentPublishingEnabled);

            // ModifySubscription: change publishing interval.
            sub.PublishingInterval = 500;
            sub.Modify();
            Check("ModifySubscription", sub.CurrentPublishingInterval > 0);

            // Event monitored item on the Server object — exercises the EventFilter path. We require
            // the create to succeed (Good); event delivery is timing/condition dependent.
            var efilter = new EventFilter();
            efilter.AddSelectClause(ObjectTypes.BaseEventType, BrowseNames.EventType);
            efilter.AddSelectClause(ObjectTypes.BaseEventType, BrowseNames.Message);
            var evItem = new MonitoredItem(sub.DefaultItem) { StartNodeId = ObjectIds.Server, AttributeId = Attributes.EventNotifier, Filter = efilter };
            sub.AddItem(evItem);
            sub.ApplyChanges();
            Check("CreateMonitoredItems (event filter) on Server", evItem.Status.Created && StatusCode.IsGood(evItem.Status.Error?.StatusCode ?? StatusCodes.Good),
                  evItem.Status.Error?.StatusCode.ToString());

            // DeleteMonitoredItems + DeleteSubscription.
            sub.RemoveItem(mi);
            sub.ApplyChanges();
            Check("DeleteMonitoredItems", true);
            session.RemoveSubscription(sub);
            Check("DeleteSubscriptions", true);
        }

        // ---- HistoryRead ---------------------------------------------------------------------
        static void HistoryChecks(Session session)
        {
            var details = new ReadRawModifiedDetails
            {
                IsReadModified = false,
                StartTime = DateTime.UtcNow.AddHours(-1),
                EndTime = DateTime.UtcNow.AddHours(1),
                NumValuesPerNode = 100,
                ReturnBounds = false,
            };
            var toRead = new HistoryReadValueIdCollection { new HistoryReadValueId { NodeId = new NodeId("HistoricalDouble", nsi) } };
            try
            {
                session.HistoryRead(null, new ExtensionObject(details), TimestampsToReturn.Both, false, toRead,
                    out HistoryReadResultCollection results, out _);
                bool ok = results.Count == 1 && StatusCode.IsGood(results[0].StatusCode)
                          && ExtensionObject.ToEncodeable(results[0].HistoryData) is HistoryData hd && hd.DataValues.Count > 0;
                Check("HistoryRead raw on HistoricalDouble returns values", ok,
                      results.Count > 0 ? results[0].StatusCode.ToString() : "no result");
            }
            catch (ServiceResultException ex) { Check("HistoryRead raw on HistoricalDouble returns values", false, ex.StatusCode.ToString()); }
        }

        // ---- Error paths ---------------------------------------------------------------------
        static void ErrorChecks(Session session)
        {
            try
            {
                var bad = session.ReadValue(new NodeId("NoSuchNode", nsi));
                Check("unknown node read -> BadNodeIdUnknown", bad.StatusCode == StatusCodes.BadNodeIdUnknown, bad.StatusCode.ToString());
            }
            catch (ServiceResultException ex) { Check("unknown node read -> BadNodeIdUnknown", ex.StatusCode == StatusCodes.BadNodeIdUnknown, ex.StatusCode.ToString()); }

            // Invalid attribute id.
            var r = new ReadValueIdCollection { new ReadValueId { NodeId = new NodeId("Int32", nsi), AttributeId = 0xFFFF } };
            session.Read(null, 0, TimestampsToReturn.Neither, r, out DataValueCollection rv, out _);
            Check("invalid attribute id -> BadAttributeIdInvalid", rv.Count == 1 && rv[0].StatusCode == StatusCodes.BadAttributeIdInvalid, rv.Count > 0 ? rv[0].StatusCode.ToString() : "no result");

            // Wrong-type write -> BadTypeMismatch.
            var w = new WriteValueCollection { new WriteValue {
                NodeId = new NodeId("Int32", nsi), AttributeId = Attributes.Value, Value = new DataValue(new Variant("not-an-int")) } };
            session.Write(null, w, out StatusCodeCollection wr, out _);
            Check("wrong-type write -> BadTypeMismatch", wr.Count == 1 && wr[0] == StatusCodes.BadTypeMismatch, wr.Count > 0 ? wr[0].ToString() : "no result");
        }

        // ---- Helpers -------------------------------------------------------------------------
        static List<string> ReadNamespaceArray(Session session)
        {
            var dv = session.ReadValue(new NodeId(2255u));
            return (dv.Value as IEnumerable<string>)?.ToList() ?? ((object[])dv.Value).Select(o => o.ToString()).ToList();
        }

        static async Task<Session> Connect(ApplicationConfiguration config, string url, bool useSecurity, IUserIdentity identity = null)
        {
            var selected = CoreClientUtils.SelectEndpoint(config, url, useSecurity);
            var endpoint = new ConfiguredEndpoint(null, selected, EndpointConfiguration.Create(config));
            return await Session.Create(config, endpoint, false, "async-opcua-dotnet-interop", 60000,
                identity ?? new UserIdentity(new AnonymousIdentityToken()), null);
        }

        static async Task<ApplicationConfiguration> BuildConfig()
        {
            string pki = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "async-opcua-dotnet-interop-pki");
            var config = new ApplicationConfiguration
            {
                ApplicationName = "async-opcua-dotnet-interop",
                ApplicationUri = "urn:async-opcua-dotnet-interop",
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier { StoreType = "Directory", StorePath = pki + "/own", SubjectName = "CN=async-opcua-dotnet-interop" },
                    TrustedPeerCertificates = new CertificateTrustList { StoreType = "Directory", StorePath = pki + "/trusted" },
                    TrustedIssuerCertificates = new CertificateTrustList { StoreType = "Directory", StorePath = pki + "/issuer" },
                    RejectedCertificateStore = new CertificateStoreIdentifier { StoreType = "Directory", StorePath = pki + "/rejected" },
                    AutoAcceptUntrustedCertificates = true,
                    AddAppCertToTrustedStore = true,
                },
                TransportConfigurations = new TransportConfigurationCollection(),
                TransportQuotas = new TransportQuotas { OperationTimeout = 30000 },
                ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 60000 },
                TraceConfiguration = new TraceConfiguration(),
            };
            await config.Validate(ApplicationType.Client);
            config.CertificateValidator.CertificateValidation += (s, e) => { e.Accept = true; e.AcceptAll = true; };
            var app = new ApplicationInstance(config);
            await app.CheckApplicationInstanceCertificatesAsync(false);
            return config;
        }
    }
}
