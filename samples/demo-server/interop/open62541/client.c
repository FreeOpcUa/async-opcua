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
#include <stdlib.h>
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
static const char *notrust_endpoint = NULL; /* set from NOTRUST_ENDPOINT for the untrusted-cert test */

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

    /* Subscribe to a writable node we control (s=Int32) and DRIVE the data-changes by writing to
     * it, rather than the server-timer-driven CurrentTime. CurrentTime only ticks on the server's
     * own publish cadence, which is racy under CI load (the previous flake); client-driven writes
     * make delivery deterministic. */
    UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
    sreq.requestedPublishingInterval = 100.0;
    UA_CreateSubscriptionResponse sresp =
        UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
    if(sresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_MonitoredItemCreateRequest mreq =
            UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(ns, "Int32"));
        mreq.requestedParameters.samplingInterval = 100.0;
        UA_MonitoredItemCreateResult mres = UA_Client_MonitoredItems_createDataChange(
            client, sresp.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, mreq, NULL,
            onDataChange, NULL);
        (void)mres;
        /* Let the subscription establish and the initial value arrive. */
        for(int i = 0; i < 20 && g_dataChanges < 1; i++)
            UA_Client_run_iterate(client, 100);
        /* Write distinct values; each is a data-change. Pump between writes so they are sampled. */
        for(UA_Int32 v = 700001; v <= 700004 && g_dataChanges < 2; v++) {
            UA_Variant sv;
            UA_Variant_init(&sv);
            UA_Variant_setScalar(&sv, &v, &UA_TYPES[UA_TYPES_INT32]);
            UA_Client_writeValueAttribute(client, UA_NODEID_STRING(ns, "Int32"), &sv);
            for(int i = 0; i < 20 && g_dataChanges < 2; i++)
                UA_Client_run_iterate(client, 100);
        }
        UA_Client_Subscriptions_deleteSingle(client, sresp.subscriptionId);
    }
    check("Subscription delivers data-change notifications", g_dataChanges >= 2, NULL);

    UA_Client_disconnect(client);
    UA_Client_delete(client);
}

/* Arrays, error paths, attribute reads, and a no-argument method call. */
static void test_service_breadth(void) {
    printf("\n[None] arrays / error paths / attributes / NoOp\n");
    UA_Client *client = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    if(UA_Client_connect(client, endpoint) != UA_STATUSCODE_GOOD) {
        check("Breadth: session established", 0, "connect failed");
        UA_Client_delete(client);
        return;
    }
    int ns = resolve_demo_namespace(client);

    /* Array round-trip: write an Int32 array and read it back. */
    if(ns > 0) {
        UA_Int32 arr[4] = {11, 22, 33, 44};
        UA_Variant wv;
        UA_Variant_init(&wv);
        UA_Variant_setArray(&wv, arr, 4, &UA_TYPES[UA_TYPES_INT32]);
        UA_StatusCode rc =
            UA_Client_writeValueAttribute(client, UA_NODEID_STRING(ns, "Int32Array"), &wv);
        check("Write Int32 array is Good", rc == UA_STATUSCODE_GOOD, NULL);
        UA_Variant rb;
        UA_Variant_init(&rb);
        rc = UA_Client_readValueAttribute(client, UA_NODEID_STRING(ns, "Int32Array"), &rb);
        int matched = rc == UA_STATUSCODE_GOOD &&
                      UA_Variant_hasArrayType(&rb, &UA_TYPES[UA_TYPES_INT32]) &&
                      rb.arrayLength == 4;
        if(matched) {
            UA_Int32 *got = (UA_Int32 *)rb.data;
            for(int i = 0; i < 4; i++)
                if(got[i] != arr[i])
                    matched = 0;
        }
        check("Array read-back matches", matched, NULL);
        UA_Variant_clear(&rb);
    }

    /* Reading an unknown node returns Bad_NodeIdUnknown. */
    UA_Variant uv;
    UA_Variant_init(&uv);
    UA_StatusCode urc = UA_Client_readValueAttribute(
        client, UA_NODEID_STRING(ns > 0 ? ns : 1, "NoSuchNode"), &uv);
    check("Read unknown node -> BadNodeIdUnknown", urc == UA_STATUSCODE_BADNODEIDUNKNOWN,
          UA_StatusCode_name(urc));
    UA_Variant_clear(&uv);

    /* Writing a read-only node (CurrentTime) is rejected. */
    UA_DateTime now = UA_DateTime_now();
    UA_Variant rov;
    UA_Variant_init(&rov);
    UA_Variant_setScalar(&rov, &now, &UA_TYPES[UA_TYPES_DATETIME]);
    UA_StatusCode wrc =
        UA_Client_writeValueAttribute(client, UA_NODEID_NUMERIC(0, 2258), &rov);
    check("Write to read-only CurrentTime is rejected", wrc != UA_STATUSCODE_GOOD,
          UA_StatusCode_name(wrc));

    /* Read the Server object's NodeClass attribute. */
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    UA_StatusCode ncrc =
        UA_Client_readNodeClassAttribute(client, UA_NODEID_NUMERIC(0, 2253), &nc);
    check("Read Server NodeClass = Object",
          ncrc == UA_STATUSCODE_GOOD && nc == UA_NODECLASS_OBJECT, NULL);

    /* Call the no-argument NoOp method. */
    if(ns > 0) {
        size_t outSize = 0;
        UA_Variant *out = NULL;
        UA_StatusCode crc = UA_Client_call(client, UA_NODEID_STRING(ns, "Functions"),
                                           UA_NODEID_STRING(ns, "NoOp"), 0, NULL, &outSize, &out);
        check("NoOp method call is Good", crc == UA_STATUSCODE_GOOD, UA_StatusCode_name(crc));
        UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);
    }

    /* --- Failure modes / error status codes (parity with the node-opcua harness, plus
     * independent confirmation of this session's server-side fixes #82/#83/#84). --- */
    if(ns > 0) {
        /* Writing the wrong data type to a typed scalar is rejected (Bad_TypeMismatch). */
        UA_String badStr = UA_STRING("not-an-int");
        UA_Variant wtv;
        UA_Variant_init(&wtv);
        UA_Variant_setScalar(&wtv, &badStr, &UA_TYPES[UA_TYPES_STRING]);
        UA_StatusCode wtrc =
            UA_Client_writeValueAttribute(client, UA_NODEID_STRING(ns, "Int32"), &wtv);
        check("Wrong-type write -> BadTypeMismatch", wtrc == UA_STATUSCODE_BADTYPEMISMATCH,
              UA_StatusCode_name(wtrc));

        /* Calling a non-existent method is rejected. */
        size_t uoSize = 0;
        UA_Variant *uo = NULL;
        UA_StatusCode umrc =
            UA_Client_call(client, UA_NODEID_STRING(ns, "Functions"),
                           UA_NODEID_STRING(ns, "NoSuchMethod"), 0, NULL, &uoSize, &uo);
        check("Call of unknown method is rejected", umrc != UA_STATUSCODE_GOOD,
              UA_StatusCode_name(umrc));
        UA_Array_delete(uo, uoSize, &UA_TYPES[UA_TYPES_VARIANT]);

        /* #82: a method called with fewer arguments than it declares returns
         * Bad_ArgumentsMissing. Add declares two Int64 inputs; we supply one. */
        UA_Int64 one = 1;
        UA_Variant amArg;
        UA_Variant_init(&amArg);
        UA_Variant_setScalar(&amArg, &one, &UA_TYPES[UA_TYPES_INT64]);
        size_t amoSize = 0;
        UA_Variant *amo = NULL;
        UA_StatusCode amrc = UA_Client_call(client, UA_NODEID_STRING(ns, "Functions"),
                                            UA_NODEID_STRING(ns, "Add"), 1, &amArg, &amoSize, &amo);
        check("Method call with missing arguments -> BadArgumentsMissing",
              amrc == UA_STATUSCODE_BADARGUMENTSMISSING, UA_StatusCode_name(amrc));
        UA_Array_delete(amo, amoSize, &UA_TYPES[UA_TYPES_VARIANT]);

        /* #83: writing a scalar to an array node (ValueRank mismatch) returns Bad_TypeMismatch. */
        UA_Int32 scalarVal = 5;
        UA_Variant vrv;
        UA_Variant_init(&vrv);
        UA_Variant_setScalar(&vrv, &scalarVal, &UA_TYPES[UA_TYPES_INT32]);
        UA_StatusCode vrrc =
            UA_Client_writeValueAttribute(client, UA_NODEID_STRING(ns, "Int32Array"), &vrv);
        check("Scalar written to an array node -> BadTypeMismatch",
              vrrc == UA_STATUSCODE_BADTYPEMISMATCH, UA_StatusCode_name(vrrc));

        /* #84: creating a monitored item on a non-existent node returns Bad_NodeIdUnknown. */
        UA_CreateSubscriptionRequest sreq = UA_CreateSubscriptionRequest_default();
        UA_CreateSubscriptionResponse sresp =
            UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
        if(sresp.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
            UA_MonitoredItemCreateRequest mreq =
                UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(ns, "NoSuchNodeXYZ"));
            UA_MonitoredItemCreateResult mres = UA_Client_MonitoredItems_createDataChange(
                client, sresp.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH, mreq, NULL, NULL, NULL);
            check("Monitored item on unknown node -> BadNodeIdUnknown",
                  mres.statusCode == UA_STATUSCODE_BADNODEIDUNKNOWN,
                  UA_StatusCode_name(mres.statusCode));
            UA_MonitoredItemCreateResult_clear(&mres);
            UA_Client_Subscriptions_deleteSingle(client, sresp.subscriptionId);
        } else {
            check("Monitored item on unknown node -> BadNodeIdUnknown", 0,
                  "subscription create failed");
        }

        /* Part 4 §5.13.2: creating more monitored items than the interop limit
         * returns the exact Bad_TooManyMonitoredItems service result. */
        UA_CreateSubscriptionResponse limitSub =
            UA_Client_Subscriptions_create(client, sreq, NULL, NULL, NULL);
        if(limitSub.responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
            UA_MonitoredItemCreateRequest limitItems[9];
            for(size_t i = 0; i < 9; i++)
                limitItems[i] = UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(ns, "Int32"));
            UA_CreateMonitoredItemsRequest cmireq;
            UA_CreateMonitoredItemsRequest_init(&cmireq);
            cmireq.subscriptionId = limitSub.subscriptionId;
            cmireq.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
            cmireq.itemsToCreate = limitItems;
            cmireq.itemsToCreateSize = 9;
            UA_CreateMonitoredItemsResponse cmiresp =
                UA_Client_MonitoredItems_createDataChanges(client, cmireq, NULL, NULL, NULL);
            check("CreateMonitoredItems over subscription limit -> BadTooManyMonitoredItems",
                  cmiresp.responseHeader.serviceResult ==
                      UA_STATUSCODE_BADTOOMANYMONITOREDITEMS,
                  UA_StatusCode_name(cmiresp.responseHeader.serviceResult));
            UA_CreateMonitoredItemsResponse_clear(&cmiresp);
            UA_Client_Subscriptions_deleteSingle(client, limitSub.subscriptionId);
        } else {
            check("CreateMonitoredItems over subscription limit -> BadTooManyMonitoredItems", 0,
                  "subscription create failed");
        }

        /* Part 4 §5.11.3.2 / Part 11: HistoryRead must reject TimestampsToReturn=Neither. */
        UA_ReadRawModifiedDetails details;
        UA_ReadRawModifiedDetails_init(&details);
        details.isReadModified = false;
        details.startTime = UA_DateTime_now() - (UA_DateTime)5 * 60 * UA_DATETIME_SEC;
        details.endTime = UA_DateTime_now() + (UA_DateTime)60 * UA_DATETIME_SEC;
        details.numValuesPerNode = 100;
        details.returnBounds = false;

        UA_HistoryReadValueId histNode;
        UA_HistoryReadValueId_init(&histNode);
        histNode.nodeId = UA_NODEID_STRING(ns, "HistoricalDouble");

        UA_HistoryReadRequest hreq;
        UA_HistoryReadRequest_init(&hreq);
        UA_ExtensionObject_setValueNoDelete(
            &hreq.historyReadDetails, &details, &UA_TYPES[UA_TYPES_READRAWMODIFIEDDETAILS]);
        hreq.timestampsToReturn = UA_TIMESTAMPSTORETURN_NEITHER;
        hreq.releaseContinuationPoints = false;
        hreq.nodesToRead = &histNode;
        hreq.nodesToReadSize = 1;
        UA_HistoryReadResponse hresp = UA_Client_Service_historyRead(client, hreq);
        check("HistoryRead with TimestampsToReturn.Neither -> BadTimestampsToReturnInvalid",
              hresp.responseHeader.serviceResult == UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID,
              UA_StatusCode_name(hresp.responseHeader.serviceResult));
        UA_HistoryReadResponse_clear(&hresp);
    }

    /* Reading an invalid attribute id is a per-operation Bad_AttributeIdInvalid. */
    {
        UA_ReadValueId rvid;
        UA_ReadValueId_init(&rvid);
        rvid.nodeId = UA_NODEID_NUMERIC(0, 2258);
        rvid.attributeId = 999;
        UA_ReadRequest rreq;
        UA_ReadRequest_init(&rreq);
        rreq.nodesToRead = &rvid;
        rreq.nodesToReadSize = 1;
        UA_ReadResponse rresp = UA_Client_Service_read(client, rreq);
        UA_StatusCode iarc = rresp.resultsSize == 1 ? rresp.results[0].status
                                                    : rresp.responseHeader.serviceResult;
        check("Read invalid attribute id -> BadAttributeIdInvalid",
              iarc == UA_STATUSCODE_BADATTRIBUTEIDINVALID, UA_StatusCode_name(iarc));
        UA_ReadResponse_clear(&rresp);
    }

    /* Browsing with a referenceTypeId that is not a ReferenceType -> Bad_ReferenceTypeIdInvalid. */
    {
        UA_BrowseRequest brq;
        UA_BrowseRequest_init(&brq);
        brq.nodesToBrowse = UA_BrowseDescription_new();
        brq.nodesToBrowseSize = 1;
        brq.nodesToBrowse[0].nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        brq.nodesToBrowse[0].referenceTypeId = UA_NODEID_NUMERIC(0, 2253); /* Server: an Object */
        brq.nodesToBrowse[0].includeSubtypes = false;
        brq.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL;
        UA_BrowseResponse brsp = UA_Client_Service_browse(client, brq);
        UA_StatusCode brrc = brsp.resultsSize == 1 ? brsp.results[0].statusCode
                                                   : brsp.responseHeader.serviceResult;
        check("Browse with a non-ReferenceType refType -> BadReferenceTypeIdInvalid",
              brrc == UA_STATUSCODE_BADREFERENCETYPEIDINVALID, UA_StatusCode_name(brrc));
        UA_BrowseResponse_clear(&brsp);
        UA_BrowseRequest_clear(&brq);
    }

    /* A browse path that resolves to nothing -> Bad_NoMatch. */
    {
        UA_RelativePathElement el;
        memset(&el, 0, sizeof(el));
        el.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
        el.includeSubtypes = true;
        el.targetName = UA_QUALIFIEDNAME(0, "NoSuchChildXYZ");
        UA_BrowsePath bp;
        UA_BrowsePath_init(&bp);
        bp.startingNode = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        bp.relativePath.elements = &el;
        bp.relativePath.elementsSize = 1;
        UA_TranslateBrowsePathsToNodeIdsRequest treq2;
        UA_TranslateBrowsePathsToNodeIdsRequest_init(&treq2);
        treq2.browsePaths = &bp;
        treq2.browsePathsSize = 1;
        UA_TranslateBrowsePathsToNodeIdsResponse tresp2 =
            UA_Client_Service_translateBrowsePathsToNodeIds(client, treq2);
        UA_StatusCode nmrc = tresp2.resultsSize == 1 ? tresp2.results[0].statusCode
                                                     : tresp2.responseHeader.serviceResult;
        check("TranslateBrowsePath with no match -> BadNoMatch",
              nmrc == UA_STATUSCODE_BADNOMATCH, UA_StatusCode_name(nmrc));
        UA_TranslateBrowsePathsToNodeIdsResponse_clear(&tresp2);
    }

    /* BrowseNext with an unrecognised continuation point -> Bad_ContinuationPointInvalid. */
    {
        UA_Byte cpbytes[4] = {1, 2, 3, 4};
        UA_ByteString cp;
        cp.length = 4;
        cp.data = cpbytes;
        UA_BrowseNextRequest bnreq;
        UA_BrowseNextRequest_init(&bnreq);
        bnreq.continuationPoints = &cp;
        bnreq.continuationPointsSize = 1;
        bnreq.releaseContinuationPoints = false;
        UA_BrowseNextResponse bnresp = UA_Client_Service_browseNext(client, bnreq);
        UA_StatusCode bnrc = bnresp.resultsSize == 1 ? bnresp.results[0].statusCode
                                                     : bnresp.responseHeader.serviceResult;
        check("BrowseNext with an invalid continuation point -> BadContinuationPointInvalid",
              bnrc == UA_STATUSCODE_BADCONTINUATIONPOINTINVALID, UA_StatusCode_name(bnrc));
        UA_BrowseNextResponse_clear(&bnresp);
    }

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

/* Authentication failure modes: wrong password and unknown user are both rejected. */
static void test_auth_failures(void) {
    printf("\n[None] authentication failure modes\n");

    UA_Client *c1 = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(c1));
    UA_StatusCode r1 = UA_Client_connectUsername(c1, endpoint, "sample1", "wrong-password");
    check("Wrong password is rejected", r1 != UA_STATUSCODE_GOOD, UA_StatusCode_name(r1));
    if(r1 == UA_STATUSCODE_GOOD)
        UA_Client_disconnect(c1);
    UA_Client_delete(c1);

    UA_Client *c2 = UA_Client_new();
    UA_ClientConfig_setDefault(UA_Client_getConfig(c2));
    UA_StatusCode r2 = UA_Client_connectUsername(c2, endpoint, "no-such-user", "whatever");
    check("Unknown user is rejected", r2 != UA_STATUSCODE_GOOD, UA_StatusCode_name(r2));
    if(r2 == UA_STATUSCODE_GOOD)
        UA_Client_disconnect(c2);
    UA_Client_delete(c2);
}

/* A server that does not auto-trust client certs must reject an unknown ("discarded") client
 * certificate on a secured handshake. Requires NOTRUST_ENDPOINT (the :4856 no-trust server). */
static void test_untrusted_cert(void) {
    if(!notrust_endpoint)
        return;
    printf("\n[Basic256Sha256 / SignAndEncrypt] untrusted client cert is rejected\n");
    UA_ByteString certificate = UA_BYTESTRING_NULL, privateKey = UA_BYTESTRING_NULL;
    UA_String subject[3] = {UA_STRING_STATIC("C=EN"), UA_STRING_STATIC("O=async-opcua"),
                            UA_STRING_STATIC("CN=open62541-untrusted-client")};
    UA_String subjectAltName[2] = {UA_STRING_STATIC("DNS:localhost"),
                                   UA_STRING_STATIC("URI:urn:open62541-untrusted-client")};
    UA_StatusCode rc = UA_CreateCertificate(
        UA_Log_Stdout, subject, 3, subjectAltName, 2, UA_CERTIFICATEFORMAT_DER, NULL,
        &privateKey, &certificate);
    if(rc != UA_STATUSCODE_GOOD) {
        check("Untrusted: client certificate generated", 0, UA_StatusCode_name(rc));
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
    cc->clientDescription.applicationUri = UA_STRING_ALLOC("urn:open62541-untrusted-client");

    rc = UA_Client_connect(client, notrust_endpoint);
    check("Untrusted client cert is rejected by the no-trust server", rc != UA_STATUSCODE_GOOD,
          rc == UA_STATUSCODE_GOOD ? "connection unexpectedly succeeded" : UA_StatusCode_name(rc));
    if(rc == UA_STATUSCODE_GOOD)
        UA_Client_disconnect(client);
    UA_Client_delete(client);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
}

int main(int argc, char **argv) {
    if(argc > 1)
        endpoint = argv[1];
    notrust_endpoint = getenv("NOTRUST_ENDPOINT");
    printf("open62541 interop smoke test against %s\n", endpoint);
    test_unsecured_services();
    test_service_breadth();
    test_username();
    test_auth_failures();
    test_secured();
    test_untrusted_cert();
    printf("\n%s: %d/%d checks passed\n",
           g_failures == 0 ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m",
           g_checks - g_failures, g_checks);
    return g_failures;
}
