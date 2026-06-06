# Quickstart Guide: Advanced OPC-UA Features

This guide illustrates how to configure and run the newly implemented Alarms, HDA, and PubSub features in the `async-opcua` framework.

## 1. Registering the Historical SQLite Storage Engine (Part 11)

To log telemetry to a local SQLite database, register the SQLite history storage engine:

```rust
use async_opcua_server::prelude::*;
use async_opcua_history_sqlite::SqliteHistoryStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::new(ServerConfig::load_default()?);

    // Instantiate SQLite reference storage engine
    let sqlite_backend = SqliteHistoryStorage::new("telemetry_history.db").await?;

    // Register backend with server History Manager
    server.history_manager().register_backend(
        NodeId::new(2, "Sensor_Temperature"),
        sqlite_backend
    );

    server.run().await?;
    Ok(())
}
```

---

## 2. Dynamic Alarm Condition Instantiation (Part 9)

To trigger and acknowledge an Alarm Condition node:

```rust
use async_opcua_server::prelude::*;

async fn trigger_temperature_alarm(
    server: &Server,
    current_temp: f64
) -> Result<(), StatusCode> {
    let address_space = server.address_space();
    
    if current_temp > 100.0 {
        // Dynamically instantiate alarm condition node
        let alarm_node_id = NodeId::new(2, "Alarm_SensorTemp_HighTemp");
        let mut condition = AlarmCondition::new(
            alarm_node_id,
            "High Temperature Alarm",
            NodeId::new(2, "Sensor_Temperature") // monitored source
        );

        // Transition state to Active
        condition.set_active(true)?;
        condition.emit_event(address_space).await?;
    }
    Ok(())
}
```

---

## 3. Starting an MQTT PubSub Publisher (Part 14)

To start publishing dataset changes cyclically over an MQTT transport mapping:

```rust
use async_opcua_pubsub::{PubSubPublisher, PubSubConnectionConfig, TransportProfile};

fn initialize_telemetry_publisher(publisher: &PubSubPublisher) {
    let config = PubSubConnectionConfig {
        connection_url: "mqtt://localhost:1883".to_string(),
        publishing_interval_ms: 1000,
        published_datasets: vec![
            NodeId::new(2, "Sensor_Temperature"),
            NodeId::new(2, "Sensor_Pressure"),
        ],
    };

    let cancel_token = tokio_util::sync::CancellationToken::new();
    publisher.start_publishing(config, cancel_token).expect("Failed to start publisher");
}
```

---

## 4. Validate the Build

Run the validation script from the repository root:

```sh
bash specs/001-implement-opc-ua-spec/validate-quickstart.sh
```
