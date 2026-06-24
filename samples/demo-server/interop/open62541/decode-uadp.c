/* Cross-stack PubSub interop check: decode an async-opcua-produced UADP NetworkMessage with
 * open62541's own decoder and confirm the publisher/group/writer IDs and the f64 payload value
 * round-trip across the two independent stacks. Part 14 §7.2.2 (UADP NetworkMessage).
 *
 * The fixture (uadp-fixture.bin) is byte-pinned by the Rust test
 * async-opcua-pubsub::codec::uadp::tests::interop_golden_uadp_vector_is_byte_stable, so if our
 * encoder drifts the Rust test fails first; if the .bin drifts from the expected values this
 * decoder fails. open62541's NetworkMessage codec is internal — see pubsub_decls.h.
 *
 * Usage:  ./decode-uadp <fixture.bin>   (exit code = number of failed checks, 0 = all passed)
 */
#include "pubsub_decls.h"
#include <stdio.h>
#include <stdlib.h>

static int g_failures = 0;
static void check(const char *name, int ok) {
    if(ok) { printf("  \x1b[32mok\x1b[0m   %s\n", name); }
    else   { g_failures++; printf("  \x1b[31mFAIL\x1b[0m %s\n", name); }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if(argc < 2) { fprintf(stderr, "usage: %s <fixture.bin>\n", argv[0]); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if(!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if(n <= 0) { fprintf(stderr, "empty fixture\n"); fclose(f); return 2; }
    UA_ByteString buf;
    UA_ByteString_init(&buf);
    buf.length = (size_t)n;
    buf.data = (UA_Byte *)malloc((size_t)n);
    if(fread(buf.data, 1, (size_t)n, f) != (size_t)n) { fclose(f); return 2; }
    fclose(f);

    printf("open62541 decoding %ld-byte UADP NetworkMessage from %s\n", n, argv[1]);

    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(nm));
    size_t offset = 0;
    UA_StatusCode rc = UA_NetworkMessage_decodeBinary(&buf, &offset, &nm, NULL);
    check("UA_NetworkMessage_decodeBinary succeeds", rc == UA_STATUSCODE_GOOD);
    if(rc != UA_STATUSCODE_GOOD) { free(buf.data); return g_failures; }

    check("consumed the whole buffer", offset == (size_t)n);
    check("publisherId is UInt16", nm.publisherIdType == UA_PUBLISHERIDTYPE_UINT16);
    check("publisherId == 2025", nm.publisherId.uint16 == 2025);
    check("groupHeader present", nm.groupHeaderEnabled);
    check("writerGroupId == 7", nm.groupHeader.writerGroupId == 7);

    UA_DataSetPayload *p = &nm.payload.dataSetPayload;
    check("exactly one DataSetMessage", nm.payloadHeader.dataSetPayloadHeader.count == 1);
    check("dataSetWriterId == 10", nm.payloadHeader.dataSetPayloadHeader.dataSetWriterIds[0] == 10);

    UA_DataSetMessage *dsm = &p->dataSetMessages[0];
    check("keyframe encoding", dsm->header.dataSetMessageType == UA_DATASETMESSAGE_DATAKEYFRAME);
    check("status enabled", dsm->header.statusEnabled);
    check("status == 0x8002", dsm->header.status == 0x8002);
    check("one field", dsm->data.keyFrameData.fieldCount == 1);
    UA_DataValue *dv = &dsm->data.keyFrameData.dataSetFields[0];
    int is_double = UA_Variant_hasScalarType(&dv->value, &UA_TYPES[UA_TYPES_DOUBLE]);
    check("field is scalar Double", is_double);
    if(is_double)
        check("field value == 72.5", *(UA_Double *)dv->value.data == 72.5);
    else
        check("field value == 72.5", 0);

    UA_NetworkMessage_clear(&nm);
    free(buf.data);
    printf(g_failures ? "\x1b[31m%d check(s) failed\x1b[0m\n" : "\x1b[32mall checks passed\x1b[0m\n",
           g_failures);
    return g_failures;
}
