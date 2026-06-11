/// MQTT transport driver implementation.
pub mod mqtt;

/// AMQP transport driver implementation.
pub mod amqp;

/// UDP multicast transport driver implementation.
pub mod udp;

/// WebSocket transport driver implementation.
pub mod websocket;

/// TSN transport driver implementation.
/// Experimental TSN transport. The AF_XDP socket is a simulated loopback
/// stub and scheduling shells out to `tc taprio`; gated behind the `tsn`
/// feature and not suitable for production use.
#[cfg(feature = "tsn")]
pub mod tsn;
