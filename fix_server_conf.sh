cat << 'CONF' > /server.conf
application_name: OPC UA Sample Server
application_uri: urn:async-opcua-Sample-Server
certificate_path: own/cert.der
certificate_validation:
  check_time: true
  trust_client_certs: false
create_sample_keypair: true
default_endpoint: null
discovery_urls:
- opc.tcp://192.168.150.205:4840/
endpoints:
  none:
    password_security_policy: null
    path: /quackdcs/infra-001
    security_level: 0
    security_mode: None
    security_policy: None
    user_token_ids:
    - ANONYMOUS
limits:
  max_array_length: 100000
  max_browse_continuation_points: 5000
  max_byte_string_length: 65535
  max_chunk_count: 5
  max_history_continuation_points: 500
  max_message_size: 327675
  max_query_continuation_points: 500
  max_sessions: 20
  max_string_length: 65535
  operational:
    max_data_sets_query_return: 1000
    max_monitored_items_per_call: 1000
    max_node_descs_per_query: 100
    max_nodes_per_browse: 1000
    max_nodes_per_history_read_data: 100
    max_nodes_per_history_read_events: 100
    max_nodes_per_history_update: 100
    max_nodes_per_method_call: 100
    max_nodes_per_node_management: 1000
    max_nodes_per_read: 10000
    max_nodes_per_register_nodes: 1000
    max_nodes_per_translate_browse_paths_to_node_ids: 100
    max_nodes_per_write: 10000
    max_references_per_browse_node: 1000
    max_references_per_references_management: 1000
    max_references_query_return: 100
    max_subscriptions_per_call: 10
  receive_buffer_size: 65535
  send_buffer_size: 65535
  subscriptions:
    default_keep_alive_count: 10
    max_keep_alive_count: 30000
    max_lifetime_count: 90000
    max_monitored_item_queue_size: 10
    max_monitored_items_per_sub: 0
    max_notifications_per_publish: 0
    max_pending_publish_requests: 20
    max_publish_requests_per_subscription: 4
    max_queued_notifications: 20
    max_subscriptions_per_session: 100
    min_publishing_interval_ms: 100
    min_sampling_interval_ms: 100
locale_ids:
- en
pki_dir: ./pki
private_key_path: private/private.pem
product_uri: urn:async-opcua-Sample-Server-Testkit
tcp_config:
  hello_timeout: 5
  host: 192.168.150.205
  port: 4840
user_tokens:
  sample_password_user:
    pass: \$argon2id\$v=19\$m=19456,t=2,p=1\$YXN5bmMtb3BjdWEtc2FtcGxlMQ\$8GTJkwyBFS+/km9tDJ431EXuaZ0w4edCnzEG0Gz2tSE
    read_diagnostics: true
    user: sample1
CONF
