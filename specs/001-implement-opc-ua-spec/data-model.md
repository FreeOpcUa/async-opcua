# Data Model: OPC-UA Compliance Entities

This document defines the logical entities, attributes, relationships, validation rules, and state transitions for the OPC-UA compliance features.

## 1. Condition Object (Alarms and Conditions - Part 9)

Represents abnormal system states in the Address Space.

### Attributes
* **NodeId** (String/Predictable): e.g. `ns=2;s=Alarm_<Device>_<Type>`. Uniquely identifies the condition.
* **ConditionName** (String): Human-readable name of the alarm condition.
* **EnabledState** (Boolean TwoStateVariable): Indicates whether the condition monitoring is active.
* **ActiveState** (Boolean TwoStateVariable): Indicates whether the abnormal state is currently present.
* **AckedState** (Boolean TwoStateVariable): Indicates whether an operator has acknowledged the alarm.
* **ConfirmedState** (Boolean TwoStateVariable): Indicates whether an operator has confirmed the alarm.
* **Retain** (Boolean): Indicates whether the server must preserve the condition state for historical event query purposes.

### Relationships
* **SourceNode**: NodeId referencing the actual variable/object being monitored (e.g., Temperature Sensor node).
* **Branch**: Maps to multiple historical events if the condition changes states frequently before acknowledgment.

### State Transitions
* **ActiveState Transition**: Can only occur when `EnabledState == true`.
* **Acknowledge call**: Moves `AckedState` to `true` if `ActiveState == true` and `EnabledState == true`.
* **Confirm call**: Moves `ConfirmedState` to `true` if `AckedState == true` and `EnabledState == true`.

---

## 2. Historical Data Record (Historical Access - Part 11)

Represents historical telemetry logged over time.

### Attributes
* **NodeId** (NodeId): Uniquely identifies the variable source.
* **SourceTimestamp** (DateTime): Microsecond-precision UTC timestamp of sensor acquisition.
* **ServerTimestamp** (DateTime): Microsecond-precision UTC timestamp when received by the server.
* **Value** (Variant Union): The telemetry payload (numeric, boolean, string, etc.).
* **StatusCode** (UInt32): OPC-UA quality status code (Good, Uncertain, Bad, etc.).

### Validation Rules
* Timestamp bounds must be evaluated using half-open intervals `[start, end)` (start inclusive, end exclusive).
* Write operations require `AccessLevel::HISTORY_UPDATE` bitflag authorization.

---

## 3. PubSub Configuration (Part 14)

Represents dataset publishing structures.

### Attributes
* **ConnectionId** (UUID/String): Uniquely identifies a transport adapter.
* **ConnectionAddress** (String): Transport URL (e.g., `mqtt://broker.local:1883` or `udp://239.0.0.1:4840`).
* **WriterGroup** (Identifier): Configures publishing interval cycle and message type (JSON vs. UADP).
* **DataSetWriter** (Identifier): Maps specific variable NodeIds to outbound DataSets.
* **PublishedDataSet** (List of NodeIds): The collection of variables grouped together in a single payload.

---

## 4. Program Object (Programs - Part 10)

Represents long-running complex execution state machines.

### Attributes
* **NodeId** (String/Predictable): e.g. `ns=2;s=Program_<Device>_<Name>`.
* **State** (ProgramStateMachineType): Encompasses:
  * **Halted**: Process is stopped and can only be reset.
  * **Ready**: Initial state, ready to start.
  * **Running**: Active execution task context.
  * **Suspended**: Paused execution context.
* **JoinHandle** (Transient): Memory pointer/handle tracking the background execution thread/task.

### State Transitions
```mermaid
state_diagram
[*] --> Ready
Ready --> Running : Start method called
Running --> Suspended : Suspend method called
Suspended --> Running : Resume method called
Running --> Halted : Halt method called or execution error
Suspended --> Halted : Halt method called
Halted --> Ready : Reset method called
```
