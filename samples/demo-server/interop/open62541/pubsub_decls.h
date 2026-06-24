/* PubSub NetworkMessage struct declarations + decode entry point.
 * These live in open62541's INTERNAL src/pubsub/ua_pubsub_networkmessage.h and are NOT in the
 * public amalgamation header, but the symbol IS exported from libopen62541. Extracted verbatim
 * from the v1.4.6 amalgamation so a standalone consumer can decode a UADP NetworkMessage.
 * Include AFTER <open62541.h> (UA_PublisherId / UA_PublisherIdType come from there). */
#ifndef INTEROP_PUBSUB_DECLS_H
#define INTEROP_PUBSUB_DECLS_H
#include <open62541.h>
_UA_BEGIN_DECLS
#define UA_NETWORKMESSAGE_MAX_NONCE_LENGTH 16

/* DataSet Payload Header */
typedef struct {
    UA_Byte count;
    UA_UInt16* dataSetWriterIds;
} UA_DataSetPayloadHeader;

/* FieldEncoding Enum  */
typedef enum {
    UA_FIELDENCODING_VARIANT = 0,
    UA_FIELDENCODING_RAWDATA = 1,
    UA_FIELDENCODING_DATAVALUE = 2,
    UA_FIELDENCODING_UNKNOWN = 3
} UA_FieldEncoding;

/* DataSetMessage Type */
typedef enum {
    UA_DATASETMESSAGE_DATAKEYFRAME = 0,
    UA_DATASETMESSAGE_DATADELTAFRAME = 1,
    UA_DATASETMESSAGE_EVENT = 2,
    UA_DATASETMESSAGE_KEEPALIVE = 3
} UA_DataSetMessageType;

/* DataSetMessage Header */
typedef struct {
    UA_Boolean dataSetMessageValid;
    UA_FieldEncoding fieldEncoding;
    UA_Boolean dataSetMessageSequenceNrEnabled;
    UA_Boolean timestampEnabled;
    UA_Boolean statusEnabled;
    UA_Boolean configVersionMajorVersionEnabled;
    UA_Boolean configVersionMinorVersionEnabled;
    UA_DataSetMessageType dataSetMessageType;
    UA_Boolean picoSecondsIncluded;
    UA_UInt16 dataSetMessageSequenceNr;
    UA_UtcTime timestamp;
    UA_UInt16 picoSeconds;
    UA_UInt16 status;
    UA_UInt32 configVersionMajorVersion;
    UA_UInt32 configVersionMinorVersion;
} UA_DataSetMessageHeader;

/**
 * DataSetMessage
 * ^^^^^^^^^^^^^^ */

typedef struct {
    UA_UInt16 fieldCount;
    UA_DataValue* dataSetFields;
    UA_ByteString rawFields;
    /* Json keys for the dataSetFields: TODO: own dataSetMessageType for json? */
    UA_String* fieldNames;
    /* This information is for proper en- and decoding needed */
    UA_DataSetMetaDataType *dataSetMetaDataType;
} UA_DataSetMessage_DataKeyFrameData;

typedef struct {
    UA_UInt16 fieldIndex;
    UA_DataValue fieldValue;
} UA_DataSetMessage_DeltaFrameField;

typedef struct {
    UA_UInt16 fieldCount;
    UA_DataSetMessage_DeltaFrameField* deltaFrameFields;
} UA_DataSetMessage_DataDeltaFrameData;

typedef struct {
    UA_DataSetMessageHeader header;
    union {
        UA_DataSetMessage_DataKeyFrameData keyFrameData;
        UA_DataSetMessage_DataDeltaFrameData deltaFrameData;
    } data;
    size_t configuredSize;
} UA_DataSetMessage;

typedef struct {
    UA_UInt16* sizes;
    UA_DataSetMessage* dataSetMessages;
} UA_DataSetPayload;

typedef enum {
    UA_NETWORKMESSAGE_DATASET = 0,
    UA_NETWORKMESSAGE_DISCOVERY_REQUEST = 1,
    UA_NETWORKMESSAGE_DISCOVERY_RESPONSE = 2
} UA_NetworkMessageType;

/**
 * UA_NetworkMessageGroupHeader
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
typedef struct {
    UA_Boolean writerGroupIdEnabled;
    UA_Boolean groupVersionEnabled;
    UA_Boolean networkMessageNumberEnabled;
    UA_Boolean sequenceNumberEnabled;
    UA_UInt16 writerGroupId;
    UA_UInt32 groupVersion; // spec: type "VersionTime"
    UA_UInt16 networkMessageNumber;
    UA_UInt16 sequenceNumber;
} UA_NetworkMessageGroupHeader;

/**
 * UA_NetworkMessageSecurityHeader
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
typedef struct {
    UA_Boolean networkMessageSigned;
    UA_Boolean networkMessageEncrypted;
    UA_Boolean securityFooterEnabled;
    UA_Boolean forceKeyReset;
    UA_UInt32 securityTokenId;      // spec: IntegerId
    UA_Byte messageNonce[UA_NETWORKMESSAGE_MAX_NONCE_LENGTH];
    UA_UInt16 messageNonceSize;
    UA_UInt16 securityFooterSize;
} UA_NetworkMessageSecurityHeader;

/**
 * UA_NetworkMessage
 * ^^^^^^^^^^^^^^^^^ */
typedef struct {
    UA_Byte version;
    UA_Boolean messageIdEnabled;
    UA_String messageId; /* For Json NetworkMessage */
    UA_Boolean publisherIdEnabled;
    UA_Boolean groupHeaderEnabled;
    UA_Boolean payloadHeaderEnabled;
    UA_Boolean dataSetClassIdEnabled;
    UA_Boolean securityEnabled;
    UA_Boolean timestampEnabled;
    UA_Boolean picosecondsEnabled;
    UA_Boolean chunkMessage;
    UA_Boolean promotedFieldsEnabled;
    UA_NetworkMessageType networkMessageType;
    UA_PublisherIdType publisherIdType;
    UA_PublisherId publisherId;
    UA_Guid dataSetClassId;

    UA_NetworkMessageGroupHeader groupHeader;

    union {
        UA_DataSetPayloadHeader dataSetPayloadHeader;
    } payloadHeader;

    UA_DateTime timestamp;
    UA_UInt16 picoseconds;
    UA_UInt16 promotedFieldsSize;
    UA_Variant* promotedFields; /* BaseDataType */

    UA_NetworkMessageSecurityHeader securityHeader;

    union {
        UA_DataSetPayload dataSetPayload;
    } payload;

    UA_ByteString securityFooter;
} UA_NetworkMessage;

UA_StatusCode UA_NetworkMessage_decodeBinary(const UA_ByteString *src, size_t *offset,
                                             UA_NetworkMessage *dst, const UA_DataTypeArray *customTypes);
void UA_NetworkMessage_clear(UA_NetworkMessage *p);
_UA_END_DECLS
#endif
