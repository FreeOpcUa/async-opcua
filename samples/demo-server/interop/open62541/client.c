/* open62541 interop conformance smoke test against the async-opcua demo server.
 *
 * A second, independent (C) OPC UA stack driving the same conformance surface as the
 * node-opcua harness: discovery/connect, browse, read, write+read-back, method call,
 * subscription data-change delivery, TranslateBrowsePaths, username auth, and a secured
 * Basic256Sha256 SignAndEncrypt session. Two independent stacks agreeing is a strong
 * conformance signal.
 *
 * Usage:  ./client <endpoint-url>
 * Exit code is the number of failed checks (0 = all passed).
 */
#include <open62541.h>
#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(const char *name, int ok, const char *detail) {
    g_checks++;
    if(ok) {
        printf("  \x1b[32mok\x1b[0m   %s\n", name);
    } else {
        g_failures++;
        printf("  \x1b[31mFAIL\x1b[0m %s%s%s\n", name, detail ? "  — " : "", detail ? detail : "");
    }
}

static const char *DEMO_NS = "urn:DemoServer";
static const char *endpoint = "opc.tcp://127.0.0.1:4855";

/* Resolve the demo namespace index by reading the server NamespaceArray (i=2255). */
static int resolve_demo_namespace(UA_Client *client) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode rc = UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(0, 2255), &v);
    int idx = -1;
    if(rc == UA_STATUSCODE_GOOD && UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String *arr = (UA_String *)v.data;
        for(size_t i = 0; i < v.arrayLength; i++) {
            if(arr[i].length == strlen(DEMO_NS) &&
               memcmp(arr[i].data, DEMO_NS, arr[i].length) == 0) {
                idx = (int)i;
                break;
            }
        }
    }
    UA_Variant_clear(&v);
    return idx;
}

static volatile int g_dataChanges = 0;
static void onDataChange(UA_Client *c, UA_UInt32 subId, void *subCtx,
                         UA_UInt32 monId, void *monCtx, UA_DataValue *value) {
    (void)c; (void)subId; (void)subCtx; (void)monId; (void)monCtx; (void)value;
    g_dataChanges++;
}

/* Anonymous, unsecured session: the bulk of the service-surface checks. */
static void test_unsecured_services(void) {
    printf("\n[None] browse / read / namespace / method / write / translate / subscription\n");
    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    if(UA_Client_connect(client, endpoint) != UA_STATUSCODE_GOOD) {
        check("None: session established", 0, "connect failed");
        UA_Client_delete(client);
        return;
    }

    /* Browse the Objects folder. */
    UA_BrowseRequest breq;
    UA_BrowseRequest_init(&breq);
    breq.requestedMaxReferencesPerNode = 0;
    breq.nodesToBrowse = UA_BrowseDescription_new();
    breq.nodesToBrowseSize = 1;
    breq.nodesToBrowse[0].nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    breq.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL;
    UA_BrowseResponse bresp = UA_Client_Service_browse(client, breq);
    check("Browse(ObjectsFolder) returns references",
          bresp.resultsSize > 0 && bresp.results[0].referencesSize > 0, NULL);
    UA_BrowseResponse_clear(&bresp);
    UA_BrowseRequest_clear(&breq);

    /* Read a standard node (CurrentTime). */
    UA_Variant val;
    UA_Variant_init(&val);
    UA_StatusCode rc = UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(0, 2258), &val);
    check("Read CurrentTime is Good", rc == UA_STATUSCODE_GOOD, NULL);
    check("CurrentTime decodes as a DateTime",
          UA_Variant_hasScalarType(&val, &UA_TYPES[UA_TYPES_DATETIME]), NULL);
    UA_Variant_clear(&val);

    /* Resolve the demo namespace and call the HelloWorld method. */
    int ns = resolve_demo_namespace(client);
    check("DemoServer namespace present", ns > 0, NULL);
    if(ns > 0) {
        size_t outSize = 0;
        UA_Variant *out = NULL;
        rc = UA_Client_call(client,
                            UA_NODEID_STRING(ns, "Functions"),
                            UA_NODEID_STRING(ns, "HelloWorld"),
                            0, NULL, &outSize, &out);
        check("HelloWorld call is Good", rc == UA_STATUSCODE_GOOD, NULL);
        int greeting = 0;
        if(rc == UA_STATUSCODE_GOOD && outSize == 1 &&
           UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_STRING])) {
            UA_String *s = (UA_String *)out[0].data;
            greeting = s->length >= 11 && memcmp(s->data, "Hello World", 11) == 0;
        }
        check("HelloWorld returns a 'Hello World' greeting", greeting, NULL);
        UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);

        /* Write a value to a writable demo variable and read it back. */
        UA_Int32 target = 424242;
        UA_Variant wv;
        UA_Variant_init(&wv);
        UA_Variant_setScalar(&wv, &target, &UA_TYPES[UA_TYPES_INT32]);
        rc = UA_Client_writeValueAttribute(client, UA_NODEID_STRING(ns, "Int32"), &wv);
        check("Write to writable Int32 is Good", rc == UA_STATUSCODE_GOOD, NULL);
        UA_Variant rb;
        UA_Variant_init(&rb);
        rc = UA_Client_readValueAttribute(client, UA_NODEID_STRING(ns, "Int32"), &rb);
        int matched = rc == UA_STATUSCODE_GOOD &&
                      UA_Variant_hasScalarType(&rb, &UA_TYPES[UA_TYPES_INT32]) &&
                      *(UA_Int32 *)rb.data == target;
        check("Read-back returns the written value", matched, NULL);
        UA_Variant_clear(&rb);
    }

    /* TranslateBrowsePaths: Server -> ServerStatus -> CurrentTime resolves to i=2258. */
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    UA_RelativePathElement elems[2];
    memset(elems, 0, sizeof(elems));
    elems[0].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    elems[0].targetName = UA_QUALIFIEDNAME(0, "ServerStatus");
    elems[1].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    elems[1].targetName = UA_QUALIFIEDNAME(0, "CurrentTime");
    bp.relativePath.elements = elems;
    bp.relativePath.elementsSize = 2;
    UA_TranslateBrowsePathsToNodeIdsRequest treq;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&treq);
    treq.browsePaths = &bp;
    treq.browsePathsSize = 1;
    UA_TranslateBrowsePathsToNodeIdsResponse tresp =
        UA_Client_Service_translateBrowsePathsToNodeIds(client, treq);
    int translated = tresp.resultsSize == 1 &&
                     tresp.results[0].statusCode == UA_STATUSCODE_GOOD &&
                     tresp.results[0].targetsSize >= 1 &&
                     tresp.results[0].targets[0].targetId.nodeId.identifierType ==
                         UA_NODEIDTYPE_NUMERIC &&
                     tresp.results[0].targets[0].targetId.nodeId.identifier.numeric == 2258;
    check("TranslateBrowsePath resolves CurrentTime (i=2258)", translated, NULL);
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&tresp);

    /* Subscribe to CurrentTime and require at least two data changes. */
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 250.0;
    UA_CreateSubscriptionResponse sresp =
        UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
    if(sresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_MonitoredItemCreateRequest mreq =
            UA_MonitoredItemCreateRequest_default(UA_NODEID_NUMERIC(0, 2258));
        mreq.requestedParameters.samplingInterval = 250.0;
        UA_MonitoredItemCreateResult mres = UA_Client_MonitoredItems_createDataChange(
            client, sresp.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, mreq, NULL,
            onDataChange, NULL);
        (void)mres;
        for(int i = 0; i < 30 && g_dataChanges < 2; i++)
            UA_Client_run_iterate(client, 200);
    }
    check("Subscription delivers data-change notifications", g_dataChanges >= 2, NULL);

    UA_Client_disconnect(client);
    UA_Client_delete(client);
}

/* Username/password identity token over the unsecured endpoint (the demo's None endpoint
 * accepts sample_password_user1). */
static void test_username(void) {
    printf("\n[None] username/password identity token\n");
    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    UA_StatusCode rc =
        UA_Client_connectUsername(client, endpoint, "sample1", "sample1_password");
    check("Username/password session established", rc == UA_STATUSCODE_GOOD, NULL);
    if(rc == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_init(&v);
        rc = UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(0, 2258), &v);
        check("Authenticated read is Good", rc == UA_STATUSCODE_GOOD, NULL);
        UA_Variant_clear(&v);
        UA_Client_disconnect(client);
    } else {
        check("Authenticated read is Good", 0, "session not established");
    }
    UA_Client_delete(client);
}

/* Secured Basic256Sha256 SignAndEncrypt session, using a freshly generated client cert
 * whose applicationUri matches its certificate SAN. */
static void test_secured(void) {
    printf("\n[Basic256Sha256 / SignAndEncrypt] secured handshake + read\n");
    UA_ByteString certificate = UA_BYTESTRING_NULL, privateKey = UA_BYTESTRING_NULL;
    UA_String subject[3] = {UA_STRING_STATIC("C=EN"), UA_STRING_STATIC("O=async-opcua"),
                            UA_STRING_STATIC("CN=open62541-interop-client")};
    UA_String subjectAltName[2] = {UA_STRING_STATIC("DNS:localhost"),
                                   UA_STRING_STATIC("URI:urn:open62541-interop-client")};
    UA_StatusCode rc = UA_CreateCertificate(
        UA_Log_Stdout, subject, 3, subjectAltName, 2, UA_CERTIFICATEFORMAT_DER, NULL,
        &privateKey, &certificate);
    if(rc != UA_STATUSCODE_GOOD) {
        check("Secured: client certificate generated", 0, UA_StatusCode_name(rc));
        return;
    }

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey, NULL, 0, NULL, 0);
    UA_CertificateVerification_AcceptAll(&cc->certificateVerification);
    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_String_clear(&cc->securityPolicyUri);
    cc->securityPolicyUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri = UA_STRING_ALLOC("urn:open62541-interop-client");

    rc = UA_Client_connect(client, endpoint);
    check("Secured session established", rc == UA_STATUSCODE_GOOD,
          rc == UA_STATUSCODE_GOOD ? NULL : UA_StatusCode_name(rc));
    if(rc == UA_STATUSCODE_GOOD) {
        UA_Variant v;
        UA_Variant_init(&v);
        rc = UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(0, 2258), &v);
        check("Secured read is Good", rc == UA_STATUSCODE_GOOD, NULL);
        UA_Variant_clear(&v);
        UA_Client_disconnect(client);
    } else {
        check("Secured read is Good", 0, "session not established");
    }
    UA_Client_delete(client);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
}

int main(int argc, char **argv) {
    if(argc > 1)
        endpoint = argv[1];
    printf("open62541 interop smoke test against %s\n", endpoint);
    test_unsecured_services();
    test_username();
    test_secured();
    printf("\n%s: %d/%d checks passed\n",
           g_failures == 0 ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m",
           g_checks - g_failures, g_checks);
    return g_failures;
}
