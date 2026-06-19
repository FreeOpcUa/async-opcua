//! GDS push model method callbacks.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use opcua_core::sync::RwLock;
use opcua_types::{ByteString, NodeId, StatusCode, Variant};

use crate::node_manager::memory::SimpleNodeManager;

use super::GDS_REGISTRY_CAPACITY;

const CERTIFICATE_MANAGER_OBJECT_ID: u32 = 22388;
const START_SIGNING_REQUEST_METHOD_ID: u32 = 22400;
const CREATE_SIGNING_REQUEST_METHOD_ID: u32 = 22403;
const REQUEST_ID_NAMESPACE: u16 = 1;

/// A CSR submitted with the GDS push `StartSigningRequest` method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsSigningRequest {
    /// Application whose certificate is being requested.
    pub application_id: NodeId,
    /// Certificate group selected for the request.
    pub certificate_group_id: NodeId,
    /// Certificate type selected for the request.
    pub certificate_type_id: NodeId,
    /// DER-encoded CSR supplied by the caller.
    pub csr_der: ByteString,
    /// Whether the caller requested private-key regeneration.
    pub regenerate_private_key: bool,
}

/// A locally generated CSR returned by `CreateSigningRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsCreatedSigningRequest {
    /// Certificate group selected for the request.
    pub certificate_group_id: NodeId,
    /// Certificate type selected for the request.
    pub certificate_type_id: NodeId,
    /// Subject name requested by the caller.
    pub subject_name: String,
    /// Whether the caller requested private-key regeneration.
    pub regenerate_private_key: bool,
    /// Caller nonce included in the CSR request.
    pub nonce: ByteString,
    /// Mock DER CSR returned by the callback.
    pub csr_der: ByteString,
}

/// In-memory registry for GDS signing requests.
#[derive(Default)]
pub struct GdsSigningRequestRegistry {
    next_request_id: AtomicU32,
    signing_requests: RwLock<HashMap<NodeId, GdsSigningRequest>>,
    signing_request_order: RwLock<VecDeque<NodeId>>,
    created_requests: RwLock<VecDeque<GdsCreatedSigningRequest>>,
}

impl GdsSigningRequestRegistry {
    /// Returns a registered signing request by request id.
    pub fn get_signing_request(&self, request_id: &NodeId) -> Option<GdsSigningRequest> {
        self.signing_requests.read().get(request_id).cloned()
    }

    /// Returns the locally generated CSRs created by `CreateSigningRequest`.
    pub fn created_signing_requests(&self) -> Vec<GdsCreatedSigningRequest> {
        self.created_requests.read().iter().cloned().collect()
    }

    fn insert_signing_request(&self, request: GdsSigningRequest) -> NodeId {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed) + 1;
        let request_id = NodeId::new(REQUEST_ID_NAMESPACE, format!("signing-request-{id}"));
        let mut signing_requests = self.signing_requests.write();
        let mut signing_request_order = self.signing_request_order.write();

        while signing_requests.len() >= GDS_REGISTRY_CAPACITY {
            let Some(oldest_request_id) = signing_request_order.pop_front() else {
                break;
            };
            signing_requests.remove(&oldest_request_id);
        }

        signing_requests.insert(request_id.clone(), request);
        signing_request_order.push_back(request_id.clone());
        request_id
    }

    fn record_created_signing_request(&self, request: GdsCreatedSigningRequest) {
        push_bounded_fifo(&mut self.created_requests.write(), request);
    }
}

fn push_bounded_fifo<T>(items: &mut VecDeque<T>, item: T) {
    if items.len() >= GDS_REGISTRY_CAPACITY {
        items.pop_front();
    }
    items.push_back(item);
}

/// Handler for GDS push model method calls.
pub struct GdsPushMethodHandler {
    registry: Arc<GdsSigningRequestRegistry>,
}

impl GdsPushMethodHandler {
    /// Creates a handler backed by the supplied in-memory registry.
    pub fn new(registry: Arc<GdsSigningRequestRegistry>) -> Self {
        Self { registry }
    }

    /// Handles `StartSigningRequest` and returns a request id `NodeId`.
    pub fn handle_start_signing_request(
        &self,
        args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        if args.len() < 5 {
            return Err(StatusCode::BadArgumentsMissing);
        }

        let request = GdsSigningRequest {
            application_id: node_id_arg(args, 0)?,
            certificate_group_id: node_id_arg(args, 1)?,
            certificate_type_id: node_id_arg(args, 2)?,
            csr_der: non_empty_byte_string_arg(args, 3)?,
            regenerate_private_key: bool_arg(args, 4)?,
        };

        let request_id = self.registry.insert_signing_request(request);
        Ok(vec![Variant::from(request_id)])
    }

    /// Handles `CreateSigningRequest` and returns a mock DER CSR `ByteString`.
    pub fn handle_create_signing_request(
        &self,
        args: &[Variant],
    ) -> Result<Vec<Variant>, StatusCode> {
        if args.len() < 5 {
            return Err(StatusCode::BadArgumentsMissing);
        }

        let certificate_group_id = node_id_arg(args, 0)?;
        let certificate_type_id = node_id_arg(args, 1)?;
        let subject_name = string_arg(args, 2)?;
        let regenerate_private_key = bool_arg(args, 3)?;
        let nonce = byte_string_arg(args, 4)?;
        let csr_der = mock_csr_der(
            &certificate_group_id,
            &certificate_type_id,
            &subject_name,
            &nonce,
        );

        self.registry
            .record_created_signing_request(GdsCreatedSigningRequest {
                certificate_group_id,
                certificate_type_id,
                subject_name,
                regenerate_private_key,
                nonce,
                csr_der: csr_der.clone(),
            });

        Ok(vec![Variant::from(csr_der)])
    }
}

/// Returns the standard CertificateManager object id used by the GDS push model.
pub fn certificate_manager_object_id() -> NodeId {
    NodeId::new(0, CERTIFICATE_MANAGER_OBJECT_ID)
}

/// Returns the standard `StartSigningRequest` method id from the task contract.
pub fn start_signing_request_method_id() -> NodeId {
    NodeId::new(0, START_SIGNING_REQUEST_METHOD_ID)
}

/// Returns the standard `CreateSigningRequest` method id from the task contract.
pub fn create_signing_request_method_id() -> NodeId {
    NodeId::new(0, CREATE_SIGNING_REQUEST_METHOD_ID)
}

/// Registers GDS push method callbacks on a simple node manager.
pub fn register_gds_push_methods(
    node_manager: &SimpleNodeManager,
) -> Arc<GdsSigningRequestRegistry> {
    let registry = Arc::new(GdsSigningRequestRegistry::default());
    register_gds_push_methods_with_registry(node_manager, registry.clone());
    registry
}

/// Registers GDS push method callbacks using the supplied registry.
pub fn register_gds_push_methods_with_registry(
    node_manager: &SimpleNodeManager,
    registry: Arc<GdsSigningRequestRegistry>,
) {
    let handler = Arc::new(GdsPushMethodHandler::new(registry));

    let create_handler = handler.clone();
    node_manager
        .inner()
        .add_method_callback_with_context(create_signing_request_method_id(), move |_ctx, args| {
            create_handler.handle_create_signing_request(args)
        });

    let start_handler = handler;
    node_manager
        .inner()
        .add_method_callback_with_context(start_signing_request_method_id(), move |_ctx, args| {
            start_handler.handle_start_signing_request(args)
        });
}

fn node_id_arg(args: &[Variant], index: usize) -> Result<NodeId, StatusCode> {
    match args.get(index) {
        Some(Variant::NodeId(node_id)) => Ok(node_id.as_ref().clone()),
        Some(_) => Err(StatusCode::BadTypeMismatch),
        None => Err(StatusCode::BadArgumentsMissing),
    }
}

fn byte_string_arg(args: &[Variant], index: usize) -> Result<ByteString, StatusCode> {
    match args.get(index) {
        Some(Variant::ByteString(value)) => Ok(value.clone()),
        Some(_) => Err(StatusCode::BadTypeMismatch),
        None => Err(StatusCode::BadArgumentsMissing),
    }
}

fn non_empty_byte_string_arg(args: &[Variant], index: usize) -> Result<ByteString, StatusCode> {
    let value = byte_string_arg(args, index)?;
    if value.is_null_or_empty() {
        Err(StatusCode::BadInvalidArgument)
    } else {
        Ok(value)
    }
}

fn bool_arg(args: &[Variant], index: usize) -> Result<bool, StatusCode> {
    match args.get(index) {
        Some(Variant::Boolean(value)) => Ok(*value),
        Some(_) => Err(StatusCode::BadTypeMismatch),
        None => Err(StatusCode::BadArgumentsMissing),
    }
}

fn string_arg(args: &[Variant], index: usize) -> Result<String, StatusCode> {
    match args.get(index) {
        Some(Variant::String(value)) if !value.is_null() => Ok(value.as_ref().to_owned()),
        Some(Variant::String(_)) => Err(StatusCode::BadInvalidArgument),
        Some(_) => Err(StatusCode::BadTypeMismatch),
        None => Err(StatusCode::BadArgumentsMissing),
    }
}

fn mock_csr_der(
    certificate_group_id: &NodeId,
    certificate_type_id: &NodeId,
    subject_name: &str,
    nonce: &ByteString,
) -> ByteString {
    let mut csr = b"async-opcua-gds-csr:".to_vec();
    csr.extend_from_slice(certificate_group_id.to_string().as_bytes());
    csr.push(b':');
    csr.extend_from_slice(certificate_type_id.to_string().as_bytes());
    csr.push(b':');
    csr.extend_from_slice(subject_name.as_bytes());
    if !nonce.is_null_or_empty() {
        csr.push(b':');
        csr.extend_from_slice(nonce.as_ref());
    }
    ByteString::from(csr)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opcua_types::{ByteString, NodeId, StatusCode, Variant};

    use crate::gds::GDS_REGISTRY_CAPACITY;

    use super::*;

    fn signing_request(index: usize) -> GdsSigningRequest {
        GdsSigningRequest {
            application_id: NodeId::new(0, index as u32),
            certificate_group_id: NodeId::new(0, 6000 + index as u32),
            certificate_type_id: NodeId::new(0, 7000 + index as u32),
            csr_der: ByteString::from(format!("csr-{index}").into_bytes()),
            regenerate_private_key: false,
        }
    }

    fn created_signing_request(index: usize) -> GdsCreatedSigningRequest {
        GdsCreatedSigningRequest {
            certificate_group_id: NodeId::new(0, 8000 + index as u32),
            certificate_type_id: NodeId::new(0, 9000 + index as u32),
            subject_name: format!("subject-{index}"),
            regenerate_private_key: false,
            nonce: ByteString::from(format!("nonce-{index}").into_bytes()),
            csr_der: ByteString::from(format!("created-csr-{index}").into_bytes()),
        }
    }

    fn start_args() -> Vec<Variant> {
        vec![
            Variant::from(NodeId::new(0, 5001)),
            Variant::from(NodeId::new(0, 5002)),
            Variant::from(NodeId::new(0, 5003)),
            Variant::from(ByteString::from(b"csr-der")),
            Variant::from(false),
        ]
    }

    #[test]
    fn start_signing_request_returns_request_node_id_and_records_csr() {
        let registry = Arc::new(GdsSigningRequestRegistry::default());
        let handler = GdsPushMethodHandler::new(registry.clone());

        let outputs = handler
            .handle_start_signing_request(&start_args())
            .expect("valid start request should succeed");

        assert_eq!(outputs.len(), 1);
        let request_id = match &outputs[0] {
            Variant::NodeId(node_id) => node_id.as_ref().clone(),
            value => panic!("expected NodeId output, got {value:?}"),
        };
        let request = registry
            .get_signing_request(&request_id)
            .expect("request should be registered");

        assert_eq!(request.application_id, NodeId::new(0, 5001));
        assert_eq!(request.csr_der, ByteString::from(b"csr-der"));
        assert!(!request.regenerate_private_key);
    }

    #[test]
    fn create_signing_request_returns_csr_bytes() {
        let registry = Arc::new(GdsSigningRequestRegistry::default());
        let handler = GdsPushMethodHandler::new(registry);

        let outputs = handler
            .handle_create_signing_request(&[
                Variant::from(NodeId::new(0, 6001)),
                Variant::from(NodeId::new(0, 6002)),
                Variant::from("CN=async-opcua"),
                Variant::from(false),
                Variant::from(ByteString::from(b"nonce")),
            ])
            .expect("valid create request should succeed");

        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            Variant::ByteString(csr) => assert!(!csr.is_null_or_empty()),
            value => panic!("expected ByteString output, got {value:?}"),
        }
    }

    #[test]
    fn signing_request_methods_reject_missing_arguments() {
        let registry = Arc::new(GdsSigningRequestRegistry::default());
        let handler = GdsPushMethodHandler::new(registry);

        assert_eq!(
            handler.handle_start_signing_request(&[]),
            Err(StatusCode::BadArgumentsMissing)
        );
        assert_eq!(
            handler.handle_create_signing_request(&[]),
            Err(StatusCode::BadArgumentsMissing)
        );
    }

    #[test]
    fn push_method_ids_match_task_contract() {
        assert_eq!(start_signing_request_method_id(), NodeId::new(0, 22400));
        assert_eq!(create_signing_request_method_id(), NodeId::new(0, 22403));
    }

    #[test]
    fn signing_request_registry_evicts_oldest_entries_when_full() {
        let registry = GdsSigningRequestRegistry::default();
        let ids = (0..GDS_REGISTRY_CAPACITY + 2)
            .map(|index| registry.insert_signing_request(signing_request(index)))
            .collect::<Vec<_>>();

        assert_eq!(
            registry.signing_requests.read().len(),
            GDS_REGISTRY_CAPACITY
        );
        assert_eq!(
            registry.signing_request_order.read().len(),
            GDS_REGISTRY_CAPACITY
        );
        assert!(registry.get_signing_request(&ids[0]).is_none());
        assert!(registry.get_signing_request(&ids[1]).is_none());
        assert!(registry.get_signing_request(&ids[2]).is_some());
        assert!(registry.get_signing_request(ids.last().unwrap()).is_some());
        assert_eq!(registry.signing_request_order.read().front(), Some(&ids[2]));
        assert_eq!(registry.signing_request_order.read().back(), ids.last());
    }

    #[test]
    fn created_signing_request_registry_evicts_oldest_entries_when_full() {
        let registry = GdsSigningRequestRegistry::default();
        for index in 0..GDS_REGISTRY_CAPACITY + 2 {
            registry.record_created_signing_request(created_signing_request(index));
        }

        let requests = registry.created_signing_requests();
        assert_eq!(requests.len(), GDS_REGISTRY_CAPACITY);
        assert_eq!(requests.first().unwrap().subject_name, "subject-2");
        assert_eq!(
            requests.last().unwrap().subject_name,
            format!("subject-{}", GDS_REGISTRY_CAPACITY + 1)
        );
    }
}
