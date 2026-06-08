//! Session-bound temporary OPC UA FileType node creation.

use crate::address_space::{AddressSpace, MethodBuilder, ObjectBuilder, VariableBuilder};
use opcua_types::{
    Argument, DataTypeId, DateTime, LocalizedText, NodeId, ObjectTypeId, StatusCode, UAString,
    VariableTypeId,
};

const DEFAULT_FOTA_NAMESPACE_URI: &str = "urn:async-opcua:fota";
const DEFAULT_MAX_BYTE_STRING_LENGTH: u32 = 64 * 1024;

/// Configuration for creating a session-bound temporary FileType node.
#[derive(Debug, Clone)]
pub struct TemporaryFileNodeConfig {
    /// Namespace index used for generated FOTA nodes.
    pub namespace_index: u16,
    /// Namespace URI registered in the address space for `namespace_index`.
    pub namespace_uri: String,
    /// Active session NodeId used to scope the temporary file.
    pub session_id: NodeId,
    /// Human-readable file name.
    pub file_name: String,
    /// Optional parent object under which the file object is attached.
    pub parent_id: Option<NodeId>,
    /// Initial file size in bytes.
    pub size: u64,
    /// Whether the file is writable.
    pub writable: bool,
    /// Whether the current user may write the file.
    pub user_writable: bool,
    /// MIME type advertised by the FileType node.
    pub mime_type: String,
    /// Maximum ByteString chunk size accepted by FileType methods.
    pub max_byte_string_length: u32,
    /// Initial last-modified timestamp.
    pub last_modified_time: DateTime,
}

impl TemporaryFileNodeConfig {
    /// Create a default FOTA temporary file node config.
    pub fn new(namespace_index: u16, session_id: NodeId, file_name: impl Into<String>) -> Self {
        Self {
            namespace_index,
            namespace_uri: DEFAULT_FOTA_NAMESPACE_URI.to_owned(),
            session_id,
            file_name: file_name.into(),
            parent_id: None,
            size: 0,
            writable: true,
            user_writable: true,
            mime_type: "application/octet-stream".to_owned(),
            max_byte_string_length: DEFAULT_MAX_BYTE_STRING_LENGTH,
            last_modified_time: DateTime::now(),
        }
    }
}

/// NodeIds created for a temporary FileType object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryFileNode {
    /// File object node id.
    pub file_id: NodeId,
    /// Size property node id.
    pub size_id: NodeId,
    /// Writable property node id.
    pub writable_id: NodeId,
    /// UserWritable property node id.
    pub user_writable_id: NodeId,
    /// OpenCount property node id.
    pub open_count_id: NodeId,
    /// MimeType property node id.
    pub mime_type_id: NodeId,
    /// MaxByteStringLength property node id.
    pub max_byte_string_length_id: NodeId,
    /// LastModifiedTime property node id.
    pub last_modified_time_id: NodeId,
    /// Open method node id.
    pub open_id: NodeId,
    /// Close method node id.
    pub close_id: NodeId,
    /// Read method node id.
    pub read_id: NodeId,
    /// Write method node id.
    pub write_id: NodeId,
    /// GetPosition method node id.
    pub get_position_id: NodeId,
    /// SetPosition method node id.
    pub set_position_id: NodeId,
}

impl TemporaryFileNode {
    /// Return every node id owned by this temporary file.
    pub fn node_ids(&self) -> Vec<NodeId> {
        let mut node_ids = vec![
            self.file_id.clone(),
            self.size_id.clone(),
            self.writable_id.clone(),
            self.user_writable_id.clone(),
            self.open_count_id.clone(),
            self.mime_type_id.clone(),
            self.max_byte_string_length_id.clone(),
            self.last_modified_time_id.clone(),
            self.open_id.clone(),
            self.close_id.clone(),
            self.read_id.clone(),
            self.write_id.clone(),
            self.get_position_id.clone(),
            self.set_position_id.clone(),
        ];
        node_ids.extend(method_argument_ids(&self.open_id, true, true));
        node_ids.extend(method_argument_ids(&self.close_id, true, false));
        node_ids.extend(method_argument_ids(&self.read_id, true, true));
        node_ids.extend(method_argument_ids(&self.write_id, true, false));
        node_ids.extend(method_argument_ids(&self.get_position_id, true, true));
        node_ids.extend(method_argument_ids(&self.set_position_id, true, false));
        node_ids
    }

    /// Create and insert a session-bound FileType object and its standard child nodes.
    pub fn create(
        address_space: &mut AddressSpace,
        config: TemporaryFileNodeConfig,
    ) -> Result<Self, StatusCode> {
        address_space.add_namespace(&config.namespace_uri, config.namespace_index);

        let node = Self::ids(&config);
        let browse_name = if config.file_name.trim().is_empty() {
            "Firmware.bin"
        } else {
            config.file_name.as_str()
        };

        let mut file_builder = ObjectBuilder::new(&node.file_id, browse_name, browse_name)
            .has_type_definition(ObjectTypeId::FileType);
        if let Some(parent_id) = config.parent_id.clone() {
            file_builder = file_builder.component_of(parent_id);
        }
        insert(file_builder.insert(address_space))?;

        insert_property(
            address_space,
            &node.file_id,
            &node.size_id,
            "Size",
            DataTypeId::UInt64,
            config.size,
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.writable_id,
            "Writable",
            DataTypeId::Boolean,
            config.writable,
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.user_writable_id,
            "UserWritable",
            DataTypeId::Boolean,
            config.user_writable,
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.open_count_id,
            "OpenCount",
            DataTypeId::UInt16,
            0_u16,
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.mime_type_id,
            "MimeType",
            DataTypeId::String,
            UAString::from(config.mime_type.as_str()),
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.max_byte_string_length_id,
            "MaxByteStringLength",
            DataTypeId::UInt32,
            config.max_byte_string_length,
        )?;
        insert_property(
            address_space,
            &node.file_id,
            &node.last_modified_time_id,
            "LastModifiedTime",
            DataTypeId::DateTime,
            config.last_modified_time,
        )?;

        insert_method(
            address_space,
            &node.file_id,
            &node.open_id,
            "Open",
            &[argument("Mode", DataTypeId::Byte)],
            &[argument("FileHandle", DataTypeId::UInt32)],
        )?;
        insert_method(
            address_space,
            &node.file_id,
            &node.close_id,
            "Close",
            &[argument("FileHandle", DataTypeId::UInt32)],
            &[],
        )?;
        insert_method(
            address_space,
            &node.file_id,
            &node.read_id,
            "Read",
            &[
                argument("FileHandle", DataTypeId::UInt32),
                argument("Length", DataTypeId::Int32),
            ],
            &[argument("Data", DataTypeId::ByteString)],
        )?;
        insert_method(
            address_space,
            &node.file_id,
            &node.write_id,
            "Write",
            &[
                argument("FileHandle", DataTypeId::UInt32),
                argument("Data", DataTypeId::ByteString),
            ],
            &[],
        )?;
        insert_method(
            address_space,
            &node.file_id,
            &node.get_position_id,
            "GetPosition",
            &[argument("FileHandle", DataTypeId::UInt32)],
            &[argument("Position", DataTypeId::UInt64)],
        )?;
        insert_method(
            address_space,
            &node.file_id,
            &node.set_position_id,
            "SetPosition",
            &[
                argument("FileHandle", DataTypeId::UInt32),
                argument("Position", DataTypeId::UInt64),
            ],
            &[],
        )?;

        Ok(node)
    }

    fn ids(config: &TemporaryFileNodeConfig) -> Self {
        let session = sanitize_identifier(&config.session_id.to_string());
        let file_name = sanitize_identifier(&config.file_name);
        let base = format!("FOTA_{}_{}", session, file_name);
        let ns = config.namespace_index;

        Self {
            file_id: NodeId::new(ns, base.clone()),
            size_id: NodeId::new(ns, format!("{base}_Size")),
            writable_id: NodeId::new(ns, format!("{base}_Writable")),
            user_writable_id: NodeId::new(ns, format!("{base}_UserWritable")),
            open_count_id: NodeId::new(ns, format!("{base}_OpenCount")),
            mime_type_id: NodeId::new(ns, format!("{base}_MimeType")),
            max_byte_string_length_id: NodeId::new(ns, format!("{base}_MaxByteStringLength")),
            last_modified_time_id: NodeId::new(ns, format!("{base}_LastModifiedTime")),
            open_id: NodeId::new(ns, format!("{base}_Open")),
            close_id: NodeId::new(ns, format!("{base}_Close")),
            read_id: NodeId::new(ns, format!("{base}_Read")),
            write_id: NodeId::new(ns, format!("{base}_Write")),
            get_position_id: NodeId::new(ns, format!("{base}_GetPosition")),
            set_position_id: NodeId::new(ns, format!("{base}_SetPosition")),
        }
    }
}

fn insert(inserted: bool) -> Result<(), StatusCode> {
    if inserted {
        Ok(())
    } else {
        Err(StatusCode::BadNodeIdExists)
    }
}

fn insert_property(
    address_space: &mut AddressSpace,
    file_id: &NodeId,
    node_id: &NodeId,
    name: &str,
    data_type: DataTypeId,
    value: impl Into<opcua_types::Variant>,
) -> Result<(), StatusCode> {
    insert(
        VariableBuilder::new(node_id, name, name)
            .property_of(file_id.clone())
            .has_type_definition(VariableTypeId::PropertyType)
            .data_type(data_type)
            .value(value)
            .insert(address_space),
    )
}

fn insert_method(
    address_space: &mut AddressSpace,
    file_id: &NodeId,
    node_id: &NodeId,
    name: &str,
    input_args: &[Argument],
    output_args: &[Argument],
) -> Result<(), StatusCode> {
    let input_args_id = NodeId::new(node_id.namespace, format!("{}_InputArguments", node_id));
    let output_args_id = NodeId::new(node_id.namespace, format!("{}_OutputArguments", node_id));
    let mut builder = MethodBuilder::new(node_id, name, name).component_of(file_id.clone());
    if !input_args.is_empty() {
        builder = builder.input_args(address_space, &input_args_id, input_args);
    }
    if !output_args.is_empty() {
        builder = builder.output_args(address_space, &output_args_id, output_args);
    }
    insert(builder.insert(address_space))
}

fn method_argument_ids(node_id: &NodeId, has_input: bool, has_output: bool) -> Vec<NodeId> {
    let mut ids = Vec::with_capacity(2);
    if has_input {
        ids.push(NodeId::new(
            node_id.namespace,
            format!("{}_InputArguments", node_id),
        ));
    }
    if has_output {
        ids.push(NodeId::new(
            node_id.namespace,
            format!("{}_OutputArguments", node_id),
        ));
    }
    ids
}

fn argument(name: &str, data_type: DataTypeId) -> Argument {
    Argument {
        name: name.into(),
        data_type: data_type.into(),
        value_rank: -1,
        array_dimensions: None,
        description: LocalizedText::null(),
    }
}

fn sanitize_identifier(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().max(1));
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "file".to_owned()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use crate::address_space::NodeType;

    use super::*;

    #[test]
    fn creates_session_bound_file_type_node() {
        let mut address_space = AddressSpace::new();
        let config = TemporaryFileNodeConfig::new(2, NodeId::new(0, "session-1"), "firmware.bin");

        let node = TemporaryFileNode::create(&mut address_space, config)
            .expect("temporary file node should be created");

        assert!(matches!(
            address_space.find(&node.file_id).as_deref(),
            Some(NodeType::Object(_))
        ));
        assert!(matches!(
            address_space.find(&node.size_id).as_deref(),
            Some(NodeType::Variable(_))
        ));
        assert!(matches!(
            address_space.find(&node.write_id).as_deref(),
            Some(NodeType::Method(_))
        ));
        for node_id in node.node_ids() {
            assert!(
                address_space.find(&node_id).is_some(),
                "expected owned node {node_id} to exist"
            );
        }
    }

    #[test]
    fn rejects_duplicate_session_file_node() {
        let mut address_space = AddressSpace::new();
        let config = TemporaryFileNodeConfig::new(2, NodeId::new(0, "session-1"), "firmware.bin");

        TemporaryFileNode::create(&mut address_space, config.clone())
            .expect("initial temporary file node should be created");
        let err = TemporaryFileNode::create(&mut address_space, config)
            .expect_err("duplicate temporary file node should fail");

        assert_eq!(err, StatusCode::BadNodeIdExists);
    }
}
