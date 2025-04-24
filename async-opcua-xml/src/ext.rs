use roxmltree::Node;

use crate::{error::XmlError, FromValue, XmlLoad};

pub(crate) trait NodeExt<'a, 'input: 'a> {
    fn first_child_with_name(&self, name: &str) -> Result<Node<'a, 'input>, XmlError>;

    fn with_name(&self, name: &str) -> impl Iterator<Item = Node<'a, 'input>>;

    fn try_attribute(&self, name: &str) -> Result<&'a str, XmlError>;

    fn try_contents(&self) -> Result<&'a str, XmlError>;
}

impl<'a, 'input: 'a> NodeExt<'a, 'input> for Node<'a, 'input> {
    fn first_child_with_name(&self, name: &str) -> Result<Node<'a, 'input>, XmlError> {
        self.with_name(name)
            .next()
            .ok_or_else(|| XmlError::missing_field(self, name))
    }

    fn with_name(&self, name: &str) -> impl Iterator<Item = Node<'a, 'input>> {
        self.children().filter(move |n| n.has_tag_name(name))
    }

    fn try_attribute(&self, name: &str) -> Result<&'a str, XmlError> {
        self.attribute(name)
            .ok_or_else(|| XmlError::missing_attribute(self, name))
    }

    fn try_contents(&self) -> Result<&'a str, XmlError> {
        self.text().ok_or_else(|| XmlError::missing_content(self))
    }
}

pub(crate) fn children_with_name<'input, T: XmlLoad<'input>>(
    node: &Node<'_, 'input>,
    name: &str,
) -> Result<Vec<T>, XmlError> {
    node.with_name(name).map(|e| T::load(&e)).collect()
}

#[allow(unused)]
pub(crate) fn first_child_with_name<'input, T: XmlLoad<'input>>(
    node: &Node<'_, 'input>,
    name: &str,
) -> Result<T, XmlError> {
    T::load(&node.first_child_with_name(name)?)
}

pub(crate) fn first_child_with_name_opt<'input, T: XmlLoad<'input>>(
    node: &Node<'_, 'input>,
    name: &str,
) -> Result<Option<T>, XmlError> {
    let Ok(child) = node.first_child_with_name(name) else {
        return Ok(None);
    };
    T::load(&child).map(|v| Some(v))
}

pub(crate) fn uint_attr(node: &Node<'_, '_>, name: &str) -> Result<Option<u64>, XmlError> {
    node.attribute(name)
        .map(|a| a.parse())
        .transpose()
        .map_err(|e| XmlError::parse_int(node, name, e))
}

pub(crate) fn int_attr(node: &Node<'_, '_>, name: &str) -> Result<Option<i64>, XmlError> {
    node.attribute(name)
        .map(|a| a.parse())
        .transpose()
        .map_err(|e| XmlError::parse_int(node, name, e))
}

pub(crate) fn value_from_contents<T: FromValue>(node: &Node<'_, '_>) -> Result<T, XmlError> {
    T::from_value(node, "content", node.try_contents()?)
}

pub(crate) fn value_from_attr<T: FromValue>(
    node: &Node<'_, '_>,
    attr: &str,
) -> Result<T, XmlError> {
    T::from_value(node, attr, node.try_attribute(attr)?)
}

#[allow(unused)]
pub(crate) fn value_from_contents_opt<T: FromValue>(
    node: &Node<'_, '_>,
) -> Result<Option<T>, XmlError> {
    let Some(c) = node.text() else {
        return Ok(None);
    };

    T::from_value(node, "content", c).map(Some)
}

pub(crate) fn value_from_attr_opt<T: FromValue>(
    node: &Node<'_, '_>,
    attr: &str,
) -> Result<Option<T>, XmlError> {
    let Some(c) = node.attribute(attr) else {
        return Ok(None);
    };

    T::from_value(node, attr, c).map(Some)
}

pub(crate) fn children_of_type<'input, T>(node: &Node<'_, 'input>) -> Result<Vec<T>, XmlError>
where
    Option<T>: XmlLoad<'input>,
{
    node.children()
        .filter_map(|n| XmlLoad::load(&n).transpose())
        .collect()
}

#[allow(unused)]
pub(crate) fn first_child_of_type<'input, T>(node: &Node<'_, 'input>) -> Result<Option<T>, XmlError>
where
    Option<T>: XmlLoad<'input>,
{
    node.children()
        .filter_map(|n| XmlLoad::load(&n).transpose())
        .next()
        .transpose()
}

#[allow(unused)]
pub(crate) fn first_child_of_type_req<'input, T>(
    node: &Node<'_, 'input>,
    ctx: &str,
) -> Result<T, XmlError>
where
    Option<T>: XmlLoad<'input>,
{
    node.children()
        .filter_map(|n| XmlLoad::load(&n).transpose())
        .next()
        .ok_or_else(|| XmlError::other(node, &format!("Expected child of type {}", ctx)))?
}

impl<T> FromValue for Vec<T>
where
    T: FromValue,
{
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        v.split_whitespace()
            .map(|v| T::from_value(node, attr, v))
            .collect()
    }
}
