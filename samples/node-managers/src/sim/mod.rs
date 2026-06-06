//! This is a very simple "simulation", that is intended
//! as a stand-in for some complex external system that a server
//! reads from.

pub mod gen;

use std::collections::HashMap;

use opcua::types::{DataTypeId, DateTime, Variant};

pub trait Generator {
    fn tick(&mut self, time: u64);

    fn get_value(&self) -> Variant;

    fn data_type(&self) -> DataTypeId;
}

struct Tag {
    value: Box<dyn Generator + Send + Sync>,
    name: String,
    description: String,
    metadata: HashMap<String, String>,
    modified_time: DateTime,
}

pub trait TagRef {
    fn add_metadata(self, key: impl Into<String>, value: impl Into<String>) -> Self;
}

impl TagRef for &mut Tag {
    fn add_metadata(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

pub struct TagMeta<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub tag: &'a str,
    pub metadata: &'a HashMap<String, String>,
    pub value: &'a dyn Generator,
    pub modified_time: DateTime,
}

pub struct Simulation {
    tags: HashMap<String, Tag>,
    last_tick: u64,
    last_tick_timestamp: DateTime,
}

impl Simulation {
    pub fn new() -> Self {
        Self {
            tags: HashMap::new(),
            last_tick: 0,
            last_tick_timestamp: DateTime::now(),
        }
    }

    pub fn get_current_tick(&self) -> (Variant, DateTime) {
        (self.last_tick.into(), self.last_tick_timestamp)
    }

    pub fn last_tick_timestamp(&self) -> DateTime {
        self.last_tick_timestamp
    }

    pub fn tick(&mut self, time: u64) {
        self.last_tick = time;
        self.last_tick_timestamp = DateTime::now();
        for tag in self.tags.values_mut() {
            tag.value.tick(time);
        }
    }

    pub fn iter_tag_meta(&self) -> impl Iterator<Item = TagMeta<'_>> + '_ {
        self.tags.iter().map(|(k, v)| TagMeta {
            name: &v.name,
            description: &v.description,
            tag: k.as_str(),
            metadata: &v.metadata,
            value: &*v.value,
            modified_time: v.modified_time,
        })
    }

    pub fn get_tag_meta<'a>(&'a self, id: &'a str) -> Option<TagMeta<'a>> {
        self.tags.get(id).map(|v| TagMeta {
            name: &v.name,
            description: &v.description,
            tag: id,
            metadata: &v.metadata,
            value: &*v.value,
            modified_time: v.modified_time,
        })
    }

    pub fn add_tag(
        &mut self,
        tag_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        sampler: impl Generator + Send + Sync + 'static,
    ) -> impl TagRef + '_ {
        let id: String = tag_id.into();
        self.tags.insert(
            id.clone(),
            Tag {
                value: Box::new(sampler),
                name: name.into(),
                description: description.into(),
                metadata: HashMap::new(),
                modified_time: DateTime::now(),
            },
        );
        let t = self.tags.get_mut(&id).unwrap();
        t.value.tick(self.last_tick);
        t
    }

    #[allow(unused)]
    pub fn modify_tag<'a>(&'a mut self, tag: &str) -> Option<impl TagRef + 'a> {
        let mut t = self.tags.get_mut(tag);
        if let Some(v) = &mut t {
            v.modified_time = DateTime::now();
        }
        t
    }

    pub fn get_tag_value(&self, tag: &str) -> Option<Variant> {
        self.tags.get(tag).map(|t| t.value.get_value())
    }
}
