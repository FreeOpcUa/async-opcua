//! Integration tests for signed and encrypted UADP PubSub messages.

use std::time::Duration;

use opcua_crypto::SecurityPolicy;
use opcua_pubsub::{
    security::{SecurityGroup, UadpSecurityCodec},
    PublisherId, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, DateTime, DecodingOptions, MessageSecurityMode,
    NamespaceMap, StatusCode, Variant,
};

fn sample_message() -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::String("line-a-publisher".to_string()),
        writer_group_id: 7,
        network_message_number: 0,
        sequence_number: 1,
        dataset_messages: vec![UadpDataSetMessage {
            dataset_writer_id: 42,
            sequence_number: 101,
            timestamp: Some(DateTime::now()),
            status: Some(StatusCode::Good),
            fields: vec![Variant::from(72.5f64), Variant::from(true)],
        }],
    }
}

#[test]
fn sign_and_encrypt_hides_payload_and_valid_group_keys_recover_it() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let message = sample_message();
    let plaintext = message.encode_to_vec(&ctx);

    let security_group = SecurityGroup::new("brewery-line-a", Duration::from_secs(3600)).unwrap();
    let group_keys = security_group.current_key_set().clone();
    let publisher = UadpSecurityCodec::new(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::PubSubAes256Ctr,
        group_keys.clone(),
    );

    let secured = publisher.encode_network_message(&message, &ctx).unwrap();

    assert_ne!(secured, plaintext);
    assert!(UadpNetworkMessage::decode(&mut &secured[..], &ctx).is_err());

    let subscriber_without_keys = UadpSecurityCodec::without_keys(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::PubSubAes256Ctr,
    );
    let missing_key_error = subscriber_without_keys
        .decode_network_message(&secured, &ctx)
        .unwrap_err();
    assert_eq!(
        missing_key_error.status(),
        StatusCode::BadSecurityChecksFailed
    );

    let subscriber_with_keys = UadpSecurityCodec::new(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::PubSubAes256Ctr,
        group_keys,
    );
    let decoded = subscriber_with_keys
        .decode_network_message(&secured, &ctx)
        .unwrap();

    assert_eq!(decoded, message);
}

#[test]
fn sign_and_encrypt_subscriber_rejects_unsigned_plaintext_uadp() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let plaintext = sample_message().encode_to_vec(&ctx);

    let security_group = SecurityGroup::new("brewery-line-a", Duration::from_secs(3600)).unwrap();
    let subscriber = UadpSecurityCodec::new(
        MessageSecurityMode::SignAndEncrypt,
        SecurityPolicy::PubSubAes256Ctr,
        security_group.current_key_set().clone(),
    );

    let error = subscriber
        .decode_network_message(&plaintext, &ctx)
        .unwrap_err();

    assert_eq!(error.status(), StatusCode::BadSecurityChecksFailed);
}

#[test]
fn secured_uadp_payload_limit_rejects_oversized_before_copy_or_decrypt() {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();
    let message = sample_message();
    let security_group = SecurityGroup::new("brewery-line-a", Duration::from_secs(3600)).unwrap();
    let group_keys = security_group.current_key_set().clone();

    for security_mode in [
        MessageSecurityMode::Sign,
        MessageSecurityMode::SignAndEncrypt,
    ] {
        let publisher = UadpSecurityCodec::new(
            security_mode,
            SecurityPolicy::PubSubAes256Ctr,
            group_keys.clone(),
        );
        let secured = publisher.encode_network_message(&message, &ctx).unwrap();

        let limited_options = DecodingOptions {
            max_secured_payload_len: 1,
            ..DecodingOptions::test()
        };
        let limited_ctx_owned = ContextOwned::new_default(NamespaceMap::new(), limited_options);
        let limited_ctx = limited_ctx_owned.context();
        let subscriber_without_keys =
            UadpSecurityCodec::without_keys(security_mode, SecurityPolicy::PubSubAes256Ctr);

        let error = subscriber_without_keys
            .decode_network_message(&secured, &limited_ctx)
            .expect_err("oversized secured UADP payload must be rejected before copy/decrypt");

        assert_eq!(error.status(), StatusCode::BadSecurityChecksFailed);
        let error = error.to_string();
        assert!(
            error.contains("max_secured_payload_len"),
            "expected secured-payload limit error for {security_mode:?}, got {error}"
        );

        let subscriber_with_keys = UadpSecurityCodec::new(
            security_mode,
            SecurityPolicy::PubSubAes256Ctr,
            group_keys.clone(),
        );
        let decoded = subscriber_with_keys
            .decode_network_message(&secured, &ctx)
            .expect("in-limit secured UADP payload must still decode");

        assert_eq!(decoded, message);
    }
}
