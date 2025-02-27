//! The [`TypeLoader`] trait and associated tools.
//!
//! When deserializing from OPC UA formats, extension objects can contain
//! a large variety of structures, including custom ones defined by extensions to the standard.
//!
//! In order to work with these, each set of types implements [`TypeLoader`], and a list
//! of type loaders are passed along during decoding.

use std::{borrow::Cow, io::Read, sync::Arc};

use chrono::TimeDelta;
use hashbrown::HashMap;

use crate::{
    BinaryDecodable, DecodingOptions, DynEncodable, EncodingResult, Error, GeneratedTypeLoader,
    NamespaceMap, NodeId, UninitializedIndex,
};

type BinaryLoadFun = fn(&mut dyn Read, &Context<'_>) -> EncodingResult<Box<dyn DynEncodable>>;

#[cfg(feature = "xml")]
type XmlLoadFun = fn(
    &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
    &Context<'_>,
) -> EncodingResult<Box<dyn DynEncodable>>;

#[cfg(feature = "json")]
type JsonLoadFun = fn(
    &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
    &Context<'_>,
) -> EncodingResult<Box<dyn DynEncodable>>;

#[derive(Default)]
/// Type used by generated type loaders to store deserialization functions.
pub struct TypeLoaderInstance {
    binary_types: HashMap<u32, BinaryLoadFun>,

    #[cfg(feature = "xml")]
    xml_types: HashMap<u32, XmlLoadFun>,

    #[cfg(feature = "json")]
    json_types: HashMap<u32, JsonLoadFun>,
}

/// Convenience method to decode a type into a DynEncodable.
pub fn binary_decode_to_enc<T: DynEncodable + BinaryDecodable>(
    stream: &mut dyn Read,
    ctx: &Context<'_>,
) -> EncodingResult<Box<dyn DynEncodable>> {
    Ok(Box::new(T::decode(stream, ctx)?))
}

#[cfg(feature = "json")]
/// Convenience method to decode a type into a DynEncodable.
pub fn json_decode_to_enc<T: DynEncodable + crate::json::JsonDecodable>(
    stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
    ctx: &Context<'_>,
) -> EncodingResult<Box<dyn DynEncodable>> {
    Ok(Box::new(T::decode(stream, ctx)?))
}

#[cfg(feature = "xml")]
/// Convenience method to decode a type into a DynEncodable.
pub fn xml_decode_to_enc<T: DynEncodable + crate::xml::XmlDecodable>(
    stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
    ctx: &Context<'_>,
) -> EncodingResult<Box<dyn DynEncodable>> {
    Ok(Box::new(T::decode(stream, ctx)?))
}

impl TypeLoaderInstance {
    /// Create a new empty type loader instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a binary type decoding function.
    pub fn add_binary_type(&mut self, data_type: u32, encoding_type: u32, fun: BinaryLoadFun) {
        self.binary_types.insert(data_type, fun);
        self.binary_types.insert(encoding_type, fun);
    }

    #[cfg(feature = "xml")]
    /// Add an XML type decoding function.
    pub fn add_xml_type(&mut self, data_type: u32, encoding_type: u32, fun: XmlLoadFun) {
        self.xml_types.insert(data_type, fun);
        self.xml_types.insert(encoding_type, fun);
    }

    #[cfg(feature = "json")]
    /// Add a JSON type decoding function.
    pub fn add_json_type(&mut self, data_type: u32, encoding_type: u32, fun: JsonLoadFun) {
        self.json_types.insert(data_type, fun);
        self.json_types.insert(encoding_type, fun);
    }

    /// Decode the type with ID `ty` using binary encoding.
    pub fn decode_binary(
        &self,
        ty: u32,
        stream: &mut dyn Read,
        context: &Context<'_>,
    ) -> Option<EncodingResult<Box<dyn DynEncodable>>> {
        let fun = self.binary_types.get(&ty)?;
        Some(fun(stream, context))
    }

    #[cfg(feature = "xml")]
    /// Decode the type with ID `ty` from a NodeSet2 XML node.
    pub fn decode_xml(
        &self,
        ty: u32,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        context: &Context<'_>,
    ) -> Option<EncodingResult<Box<dyn DynEncodable>>> {
        let fun = self.xml_types.get(&ty)?;
        Some(fun(stream, context))
    }

    #[cfg(feature = "json")]
    /// Decode the type with ID `ty` using JSON encoding.
    pub fn decode_json(
        &self,
        ty: u32,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        context: &Context<'_>,
    ) -> Option<EncodingResult<Box<dyn DynEncodable>>> {
        let fun = self.json_types.get(&ty)?;
        Some(fun(stream, context))
    }
}

/// Convenience trait for a type loader using a static [`TypeLoaderInstance`] and
/// namespace known at compile time.
///
/// Types implementing this blanket implement [`TypeLoader`]
pub trait StaticTypeLoader {
    /// Get the type loader instance used by this type loader.
    fn instance() -> &'static TypeLoaderInstance;

    /// Get the namespace this type loader manages.
    fn namespace() -> &'static str;
}

impl<T> TypeLoader for T
where
    T: StaticTypeLoader + Send + Sync + 'static,
{
    #[cfg(feature = "xml")]
    fn load_from_xml(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let idx = ctx.namespaces().get_index(Self::namespace())?;
        if idx != node_id.namespace {
            return None;
        }
        let Some(num_id) = node_id.as_u32() else {
            return Some(Err(Error::decoding(
                "Unsupported encoding ID. Only numeric encoding IDs are currently supported",
            )));
        };
        Self::instance().decode_xml(num_id, stream, ctx)
    }

    #[cfg(feature = "json")]
    fn load_from_json(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let idx = ctx.namespaces().get_index(Self::namespace())?;
        if idx != node_id.namespace {
            return None;
        }
        let Some(num_id) = node_id.as_u32() else {
            return Some(Err(Error::decoding(
                "Unsupported encoding ID. Only numeric encoding IDs are currently supported",
            )));
        };
        Self::instance().decode_json(num_id, stream, ctx)
    }

    fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn Read,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let idx = ctx.namespaces().get_index(Self::namespace())?;
        if idx != node_id.namespace {
            return None;
        }
        let Some(num_id) = node_id.as_u32() else {
            return Some(Err(Error::decoding(
                "Unsupported encoding ID. Only numeric encoding IDs are currently supported",
            )));
        };
        Self::instance().decode_binary(num_id, stream, ctx)
    }

    fn priority(&self) -> TypeLoaderPriority {
        TypeLoaderPriority::Generated
    }
}

/// Owned variant of [Context], this is stored by clients and servers, which
/// call the [ContextOwned::context] method to produce a [Context]
/// for decoding/encoding.
pub struct ContextOwned {
    namespaces: NamespaceMap,
    loaders: TypeLoaderCollection,
    options: DecodingOptions,
}

impl std::fmt::Debug for ContextOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextOwned")
            .field("namespaces", &self.namespaces)
            .field("options", &self.options)
            .finish()
    }
}

impl ContextOwned {
    /// Create a new context.
    pub fn new(
        namespaces: NamespaceMap,
        loaders: TypeLoaderCollection,
        options: DecodingOptions,
    ) -> Self {
        Self {
            namespaces,
            loaders,
            options,
        }
    }

    /// Create a new context, including the core type loader.
    pub fn new_default(namespaces: NamespaceMap, options: DecodingOptions) -> Self {
        Self::new(namespaces, TypeLoaderCollection::new(), options)
    }

    /// Return a context for decoding.
    pub fn context(&self) -> Context<'_> {
        Context {
            namespaces: &self.namespaces,
            loaders: &self.loaders,
            options: self.options.clone(),
            aliases: None,
            index_map: None,
        }
    }

    /// Get the namespace map.
    pub fn namespaces(&self) -> &NamespaceMap {
        &self.namespaces
    }

    /// Get the namespace map mutably.
    pub fn namespaces_mut(&mut self) -> &mut NamespaceMap {
        &mut self.namespaces
    }

    /// Get the decoding options.
    pub fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// Get the decoding options mutably.
    pub fn options_mut(&mut self) -> &mut DecodingOptions {
        &mut self.options
    }

    /// Get a mutable reference to the type loaders.
    pub fn loaders_mut(&mut self) -> &mut TypeLoaderCollection {
        &mut self.loaders
    }
}

impl Default for ContextOwned {
    fn default() -> Self {
        Self::new_default(Default::default(), Default::default())
    }
}

#[derive(Clone)]
/// Wrapper type around a vector of type loaders that maintains
/// sorted order according to the `priority` of each type loader.
pub struct TypeLoaderCollection {
    loaders: Vec<Arc<dyn TypeLoader>>,
}

impl Default for TypeLoaderCollection {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeLoaderCollection {
    /// Create a new type loader collection containing only the
    /// generated type loader.
    pub fn new() -> Self {
        Self {
            loaders: vec![Arc::new(GeneratedTypeLoader)],
        }
    }

    /// Create a new type loader collection without any type loaders at all,
    /// not even the built-ins. This is usually only useful for testing.
    pub fn new_empty() -> Self {
        Self {
            loaders: Vec::new(),
        }
    }

    /// Add a type loader to the collection.
    pub fn add_type_loader(&mut self, loader: impl TypeLoader + 'static) {
        self.add(Arc::new(loader));
    }

    /// Add a type loader to the collection.
    pub fn add(&mut self, loader: Arc<dyn TypeLoader>) {
        let priority = loader.priority();
        for i in 0..self.loaders.len() {
            if self.loaders[i].priority() > priority {
                self.loaders.insert(i, loader);
                return;
            }
        }
        self.loaders.push(loader);
    }

    /// Iterate over the type loaders.
    pub fn iter(&self) -> <&Self as IntoIterator>::IntoIter {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a TypeLoaderCollection {
    type Item = &'a Arc<dyn TypeLoader>;

    type IntoIter = <&'a [Arc<dyn TypeLoader>] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.loaders.iter()
    }
}

#[derive(Clone)]
/// Decoding/encoding context. Lifetime is typically tied to an instance of [ContextOwned].
pub struct Context<'a> {
    namespaces: &'a NamespaceMap,
    loaders: &'a TypeLoaderCollection,
    options: DecodingOptions,
    aliases: Option<&'a HashMap<String, String>>,
    index_map: Option<&'a HashMap<u16, u16>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Priority of the given type loader.
/// Type loaders should be sorted by this value, to ensure that
/// correct implementations are selected if multiple type loaders
/// handle the same type.
pub enum TypeLoaderPriority {
    /// Reserved for the core namespace.
    Core,
    /// Any generated type loader.
    Generated,
    /// Some form of dynamic type loader, can specify a custom
    /// priority greater than 1.
    Dynamic(u32),
    /// Fallback, will always be sorted last.
    Fallback,
}

impl TypeLoaderPriority {
    /// Get the priority of the type loader as a number.
    pub fn priority(&self) -> u32 {
        match self {
            Self::Core => 0,
            Self::Generated => 1,
            Self::Dynamic(v) => *v,
            Self::Fallback => u32::MAX,
        }
    }
}

impl PartialOrd for TypeLoaderPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TypeLoaderPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority().cmp(&other.priority())
    }
}

/// Trait for a collection of types.
/// Each method in this trait should try to decode the passed stream/body
/// into a [DynEncodable], and return `None` if the `node_id` does not match
/// any variant. It should only return an error if the `node_id` is a match,
/// but decoding failed.
pub trait TypeLoader: Send + Sync {
    #[cfg(feature = "xml")]
    /// Load the type given by `node_id` from XML by trying each
    /// registered type loader until one returns `Some`.
    fn load_from_xml(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>>;

    #[cfg(feature = "json")]
    /// Load the type given by `node_id` from JSON by trying each
    /// registered type loader until one returns `Some`.
    fn load_from_json(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>>;

    /// Load the type given by `node_id` from Binary by trying each
    /// registered type loader until one returns `Some`.
    fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn Read,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>>;

    /// Get the priority of this type loader.
    fn priority(&self) -> TypeLoaderPriority {
        TypeLoaderPriority::Generated
    }
}

impl<'a> Context<'a> {
    /// Constructor. Prefer to use `ContextOwned` to avoid having to juggle
    /// NamespaceMap and TypeLoaderCollection yourself.
    pub fn new(
        namespaces: &'a NamespaceMap,
        loaders: &'a TypeLoaderCollection,
        options: DecodingOptions,
    ) -> Self {
        Self {
            namespaces,
            loaders,
            options,
            aliases: None,
            index_map: None,
        }
    }

    #[cfg(feature = "json")]
    /// Try to load a type dynamically from JSON, returning an error if no
    /// matching type loader was found.
    pub fn load_from_json(
        &self,
        node_id: &NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn Read>,
    ) -> crate::EncodingResult<crate::ExtensionObject> {
        for loader in self.loaders {
            if let Some(r) = loader.load_from_json(node_id, stream, self) {
                return Ok(crate::ExtensionObject { body: Some(r?) });
            }
        }
        Err(Error::decoding(format!(
            "No type loader defined for {node_id}"
        )))
    }

    /// Try to load a type dynamically from OPC-UA binary, returning an error if no
    /// matching type loader was found.
    pub fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn Read,
    ) -> crate::EncodingResult<crate::ExtensionObject> {
        for loader in self.loaders {
            if let Some(r) = loader.load_from_binary(node_id, stream, self) {
                return Ok(crate::ExtensionObject { body: Some(r?) });
            }
        }
        Err(Error::decoding(format!(
            "No type loader defined for {node_id}"
        )))
    }

    #[cfg(feature = "xml")]
    /// Try to load a type dynamically from XML, returning an error if no
    /// matching type loader was found.
    pub fn load_from_xml(
        &self,
        node_id: &NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
    ) -> crate::EncodingResult<crate::ExtensionObject> {
        for loader in self.loaders {
            if let Some(r) = loader.load_from_xml(node_id, stream, self) {
                return Ok(crate::ExtensionObject { body: Some(r?) });
            }
        }
        Err(Error::decoding(format!(
            "No type loader defined for {node_id}"
        )))
    }

    /// Get the decoding options.
    pub fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// Get the namespace map.
    pub fn namespaces(&self) -> &'a NamespaceMap {
        self.namespaces
    }

    /// Set the index map used for resolving namespace indices during XML decoding.
    pub fn set_index_map(&mut self, index_map: &'a HashMap<u16, u16>) {
        self.index_map = Some(index_map);
    }

    /// Set the alias table used for resolving node ID aliases during XML decoding.
    pub fn set_aliases(&mut self, aliases: &'a HashMap<String, String>) {
        self.aliases = Some(aliases);
    }

    /// Resolve the given namespace index to the real, server namespace index.
    /// Used when loading nodeset files.
    pub fn resolve_namespace_index(
        &self,
        index_in_node_set: u16,
    ) -> Result<u16, UninitializedIndex> {
        if index_in_node_set == 0 {
            return Ok(0);
        }

        let Some(index_map) = self.index_map else {
            return Ok(index_in_node_set);
        };
        let Some(idx) = index_map.get(&index_in_node_set) else {
            return Err(UninitializedIndex(index_in_node_set));
        };
        Ok(*idx)
    }

    /// Look up namespace index in reverse, finding the index in the node set
    /// given the index in the server.
    pub fn resolve_namespace_index_inverse(
        &self,
        index_in_server: u16,
    ) -> Result<u16, UninitializedIndex> {
        if index_in_server == 0 {
            return Ok(0);
        }

        let Some(index_map) = self.index_map else {
            return Ok(index_in_server);
        };
        let Some((idx, _)) = index_map.iter().find(|(_, &v)| v == index_in_server) else {
            return Err(UninitializedIndex(index_in_server));
        };
        Ok(*idx)
    }

    /// Resolve a node ID alias, if the alias table is registered.
    /// Only used for XML decoding when loading nodeset files.
    pub fn resolve_alias<'b>(&self, node_id_str: &'b str) -> &'b str
    where
        'a: 'b,
    {
        if let Some(aliases) = self.aliases {
            if let Some(alias) = aliases.get(node_id_str) {
                return alias.as_str();
            }
        }
        node_id_str
    }

    /// Resolve a node ID alias in inverse, getting the alias value given the node ID.
    pub fn resolve_alias_inverse<'b>(&self, node_id_str: &'b str) -> &'b str
    where
        'a: 'b,
    {
        if let Some(aliases) = self.aliases {
            for (k, v) in aliases.iter() {
                if v == node_id_str {
                    return k.as_str();
                }
            }
        }
        node_id_str
    }

    /// Produce a copy of self with zero client_offset, or a borrow if
    /// the offset is already zero.
    pub fn with_zero_offset(&self) -> Cow<'_, Self> {
        if self.options.client_offset.is_zero() {
            Cow::Borrowed(self)
        } else {
            Cow::Owned(Self {
                namespaces: self.namespaces,
                loaders: self.loaders,
                options: DecodingOptions {
                    client_offset: TimeDelta::zero(),
                    ..self.options.clone()
                },
                aliases: self.aliases,
                index_map: self.index_map,
            })
        }
    }
}
