# Quickstart: alarm that monitors a source variable

## Declare an alarm bound to a source Variable

```rust ignore
// A writable process variable...
let source = NodeId::new(2, "Temperature");
// ...and a limit alarm with a High limit.
let alarm = ExclusiveLimitAlarmType::new(/* ... limits incl. High = 80.0, deadband ... */);

// Bind the alarm to the source in one call: sets InputNode + HasCondition + registers the index.
node_manager.monitor_alarm_source(&source, alarm);
// (optional) poll the source out-of-band every 500 ms as well:
// node_manager.monitor_alarm_source_sampled(&source, alarm, Duration::from_millis(500));
```

## It now self-triggers

```rust ignore
// A client (or the server) writes a value above the High limit to the source.
session.write(&[WriteValue::value(source.clone(), 95.0)]).await?;
// → the alarm becomes Active(High) and an AlarmEvent is delivered to subscribers —
//   no update_value call needed.

session.write(&[WriteValue::value(source.clone(), 20.0)]).await?;
// → the alarm returns to Inactive (honoring deadband) and a clearing event is delivered.
```

## Browse the binding

- Read the alarm's `InputNode` property → returns the source NodeId (Part 9 §5.8.2).
- Browse the source node's `HasCondition` references → reach the bound alarm (Part 9 §4.4).

## Backwards compatible

- An alarm with no binding still works exactly as before via `alarm.update_value(&mut space, v)`.
- A disabled alarm does not fire when its source changes.
- Writing a non-numeric / bad-status value to the source never panics and never fails the write.
