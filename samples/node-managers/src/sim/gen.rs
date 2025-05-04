use opcua::types::{DataTypeId, Variant};

use super::Generator;

#[derive(Default)]
pub struct SineValue(f64);

impl Generator for SineValue {
    fn get_value(&self) -> opcua::types::Variant {
        self.0.into()
    }

    fn tick(&mut self, time: u64) {
        self.0 = ((time as f64) / 50.0).sin()
    }

    fn data_type(&self) -> DataTypeId {
        DataTypeId::Double
    }
}

#[derive(Default)]
pub struct CosValue(f64);

impl Generator for CosValue {
    fn get_value(&self) -> opcua::types::Variant {
        self.0.into()
    }

    fn tick(&mut self, time: u64) {
        self.0 = ((time as f64) / 50.0).cos()
    }

    fn data_type(&self) -> DataTypeId {
        DataTypeId::Double
    }
}

#[derive(Default)]
pub struct JustLinearTime(u64);

impl Generator for JustLinearTime {
    fn get_value(&self) -> opcua::types::Variant {
        self.0.into()
    }

    fn tick(&mut self, time: u64) {
        self.0 = time;
    }

    fn data_type(&self) -> DataTypeId {
        DataTypeId::UInt64
    }
}

pub struct SomeFunction {
    last: Variant,
    fun: Box<dyn Fn(u64) -> Variant + Send + Sync>,
    data_type: DataTypeId,
}

impl SomeFunction {
    pub fn new(
        fun: impl Fn(u64) -> Variant + Send + Sync + 'static,
        data_type: DataTypeId,
    ) -> Self {
        Self {
            last: Variant::Empty,
            fun: Box::new(fun),
            data_type,
        }
    }
}

impl Generator for SomeFunction {
    fn get_value(&self) -> Variant {
        self.last.clone()
    }

    fn tick(&mut self, time: u64) {
        self.last = (*self.fun)(time)
    }

    fn data_type(&self) -> DataTypeId {
        self.data_type
    }
}
