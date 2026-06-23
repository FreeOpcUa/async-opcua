# Conformance Audit: OPC UA Part 3 "Address Space Model" (v1.05.06)

This document contains the conformance audit results of the `async-opcua` Rust codebase against OPC UA Part 3, focusing on specified NodeClass attributes and semantics.

## Summary of Candidate Divergences

1. **Unmodeled Base Attributes**
   * **Location:** [base.rs:14-29](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L14-L29)
   * **Details:** The optional base attributes `RolePermissions`, `UserRolePermissions`, and `AccessRestrictions` (Table 7) are entirely un-modeled in the `Base` struct and cannot be set or read (returning `BadAttributeIdInvalid`).
2. **Missing `ValueRank` Writable Support in `Variable`**
   * **Location:** [variable.rs:245-283](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L245-L283)
   * **Details:** Clients cannot write/modify `ValueRank` via `set_attribute` on a `Variable` node (it falls through to `Base` and returns `BadAttributeIdInvalid`), whereas `VariableType` does support writing `ValueRank` in [variable_type.rs:135](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L135).
3. **No Validation of `ValueRank` vs `ArrayDimensions` Constraints**
   * **Location:** [variable.rs:827-830](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L827-L830), [variable_type.rs:284-287](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L284-L287)
   * **Details:** Neither `Variable` nor `VariableType` enforces the constraint that the length of `ArrayDimensions` must equal `ValueRank` when `ValueRank > 0`.
4. **No Validation that `ArrayDimensions` is Null when `ValueRank <= 0`**
   * **Location:** [variable.rs:154](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L154), [variable_type.rs:69](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L69)
   * **Details:** The rule that `ArrayDimensions` must be null/omitted if `ValueRank <= 0` (or if not an array) is not enforced; both attributes can be set independently to inconsistent values.
5. **No Validation of `ValueRank` Semantics**
   * **Location:** [variable_type.rs:135](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L135)
   * **Details:** No range or semantic check is done to restrict `ValueRank` to the standardized values (-1, -2, -3, 0, >=1) when set programmatically or via `set_attribute` (e.g. `VariableType` accepts any `i32`).
6. **No Enforcement that Symmetric ReferenceType has No Inverse Name**
   * **Location:** [reference_type.rs:50-56](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/reference_type.rs#L50-L56)
   * **Details:** The rule that symmetric ReferenceTypes must omit the `InverseName` attribute is not enforced; the struct and its builder allow both `symmetric = true` and `inverse_name = Some(...)` to be populated simultaneously.
7. **No Enforcement Against Instantiating Abstract ObjectTypes or VariableTypes**
   * **Location:** [memory_mgr_impl.rs:56-130](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L56-L130)
   * **Details:** The server's `add_nodes` service implementation does not check if the referenced `TypeDefinitionNode` is abstract, allowing clients to instantiate abstract type definitions.
8. **No Enforcement Against Using Abstract ReferenceTypes**
   * **Location:** [memory_mgr_impl.rs:163-253](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L163-L253)
   * **Details:** The server's `add_references` service implementation only checks that the ReferenceType exists, but does not check its `is_abstract` attribute, allowing references to use abstract reference types directly.

---

## Detailed Findings Tables

### §5.2 Base NodeClass
| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **NodeId** (M) | §5.2 / 2011 | [base.rs:16](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L16) | HONORED | Modeled as a non-optional field. |
| **NodeClass** (M) | §5.2 / 2012 | [base.rs:18](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L18) | HONORED | Modeled as a non-optional field. |
| **BrowseName** (M) | §5.2 / 2013 | [base.rs:20](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L20) | HONORED | Modeled as a non-optional field. |
| **DisplayName** (M) | §5.2 / 2014 | [base.rs:22](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L22) | HONORED | Modeled as a non-optional field. |
| **Description** (O) | §5.2 / 2015 | [base.rs:24](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L24) | HONORED | Modeled as `Option<LocalizedText>`. |
| **WriteMask** (O) | §5.2 / 2016 | [base.rs:26](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L26) | HONORED | Modeled as `Option<u32>`. |
| **UserWriteMask** (O) | §5.2 / 2017 | [base.rs:28](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L28) | HONORED | Modeled as `Option<u32>`. |
| **RolePermissions** (O) | §5.2 / 2018 | [base.rs:14-29](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L14-L29) | CANDIDATE DIVERGENCE | Attribute is not modeled in the `Base` struct or attribute handling. |
| **UserRolePermissions** (O) | §5.2 / 2019 | [base.rs:14-29](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L14-L29) | CANDIDATE DIVERGENCE | Attribute is not modeled in the `Base` struct or attribute handling. |
| **AccessRestrictions** (O) | §5.2 / 2020 | [base.rs:14-29](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/base.rs#L14-L29) | CANDIDATE DIVERGENCE | Attribute is not modeled in the `Base` struct or attribute handling. |

### §5.6 Variable/VariableType NodeClass
| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Variable: Value** (M) | §5.6 / 2696 | [variable.rs:151](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L151) | HONORED | Modeled as `DataValue` and verified mandatory. |
| **Variable: DataType** (M) | §5.6 / 2701 | [variable.rs:148](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L148) | HONORED | Modeled as `NodeId` and verified mandatory. |
| **Variable: ValueRank** (M) | §5.6 / 2704 | [variable.rs:150](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L150) | HONORED | Modeled as `i32` and verified mandatory. |
| **Variable: AccessLevel** (M) | §5.6 / 2735 | [variable.rs:152](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L152) | HONORED | Modeled as `u8` and verified mandatory. |
| **Variable: UserAccessLevel** (M) | §5.6 / 2742 | [variable.rs:153](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L153) | HONORED | Modeled as `u8` and verified mandatory. |
| **Variable: Historizing** (M) | §5.6 / 2756 | [variable.rs:149](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L149) | HONORED | Modeled as `bool` and verified mandatory. |
| **VariableType: Value** (O) | §5.6 / 3060 | [variable_type.rs:68](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L68) | HONORED | Modeled as `Option<DataValue>` and verified optional. |
| **VariableType: DataType** (M) | §5.6 / 3064 | [variable_type.rs:65](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L65) | HONORED | Modeled as `NodeId` and verified mandatory. |
| **VariableType: ValueRank** (M) | §5.6 / 3067 | [variable_type.rs:67](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L67) | HONORED | Modeled as `i32` and verified mandatory. |
| **VariableType: IsAbstract** (M) | §5.6 / 3091 | [variable_type.rs:66](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L66) | HONORED | Modeled as `bool` and verified mandatory. |
| **Variable/VariableType: ArrayDimensions** (O) | §5.6 / 2719, 3081 | [variable.rs:154](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L154), [variable_type.rs:69](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L69) | HONORED | Modeled as `Option<Vec<u32>>` and verified optional. |
| **Variable: MinimumSamplingInterval** (O) | §5.6 / 2748 | [variable.rs:155](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L155) | HONORED | Modeled as `Option<f64>` and verified optional. |
| **ValueRank Semantics** | §5.6 / 2707-2716, 3069-3078 | [value_rank.rs:40-47](file:///home/quackdcs/async-opcua/async-opcua-types/src/value_rank.rs#L40-L47) | HONORED | Standard constants (`SCALAR` = -1, `ONE_OR_MORE_DIMENSIONS` = 0, `ANY` = -2, `SCALAR_OR_ONE_DIMENSION` = -3) are modeled. |
| **ValueRank validation/enforcement** | §5.6 / 2704, 3067 | [variable.rs:806](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L806), [variable_type.rs:135](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L135) | CANDIDATE DIVERGENCE | No validation of ValueRank semantics is done when set or written. In VariableType, `set_attribute` accepts any `i32`. |
| **ArrayDimensions length equals ValueRank** | §5.6 / 2721, 3084 | [variable.rs:154](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L154), [variable_type.rs:69](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L69) | CANDIDATE DIVERGENCE | The rule that `ArrayDimensions` length must equal `ValueRank` when `ValueRank > 0` is not enforced. |
| **ArrayDimensions null/omitted constraints** | §5.6 / 2722, 3085 | [variable.rs:154](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L154), [variable_type.rs:69](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable_type.rs#L69) | CANDIDATE DIVERGENCE | Not enforced; both attributes can be set independently to inconsistent values (e.g. `ArrayDimensions` set when `ValueRank <= 0`). |
| **Variable ValueRank writable via set_attribute** | §5.6 / 2704 | [variable.rs:245-283](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/variable.rs#L245-L283) | CANDIDATE DIVERGENCE | Variable's `set_attribute` does not handle `ValueRank`, returning `BadAttributeIdInvalid` instead of supporting writes. |
| **Instantiation of abstract VariableTypes** | §5.6 / 3092 | [memory_mgr_impl.rs:56-130](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L56-L130) | CANDIDATE DIVERGENCE | The `add_nodes` implementation does not check if the variable's type definition is abstract. |

### §5.5 Object/ObjectType
| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Object: EventNotifier** (M) | §5.5 / 2482 | [object.rs:63](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/object.rs#L63) | HONORED | Modeled as a mandatory attribute, verified in attributes check. |
| **ObjectType: IsAbstract** (M) | §5.5 / 2568 | [object_type.rs:43](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/object_type.rs#L43) | HONORED | Modeled as a mandatory attribute, verified in attributes check. |
| **Instantiation of abstract ObjectTypes** | §5.5 / 2569 | [memory_mgr_impl.rs:56-130](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L56-L130) | CANDIDATE DIVERGENCE | The `add_nodes` implementation does not check if the object type definition is abstract. |

### §5.3 ReferenceType NodeClass + §7 Standard ReferenceTypes
| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **ReferenceType: Symmetric** (M) | §5.3 / 2232 | [reference_type.rs:53](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/reference_type.rs#L53) | HONORED | Modeled as a mandatory attribute. |
| **ReferenceType: IsAbstract** (M) | §5.3 / 2227 | [reference_type.rs:54](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/reference_type.rs#L54) | HONORED | Modeled as a mandatory attribute. |
| **ReferenceType: InverseName** (O) | §5.3 / 2239 | [reference_type.rs:55](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/reference_type.rs#L55) | HONORED | Modeled as optional `Option<LocalizedText>`. |
| **Symmetric reference has no inverse name** | §5.3 / 2274 | [reference_type.rs:50-56](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/reference_type.rs#L50-L56) | CANDIDATE DIVERGENCE | Both `symmetric = true` and `inverse_name = Some(...)` can be populated simultaneously without constraint. |
| **Abstract reference types cannot be used directly** | §5.3 / 2228, 2267 | [memory_mgr_impl.rs:163-253](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L163-L253) | CANDIDATE DIVERGENCE | `add_references` only verifies that the reference type exists, but does not check if it is abstract, allowing its direct use. |

### §5.7 Method
| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Method: Executable** (M) | §5.7 / 3191 | [method.rs:104](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/method.rs#L104) | HONORED | Modeled as a mandatory attribute. |
| **Method: UserExecutable** (M) | §5.7 / 3197 | [method.rs:105](file:///home/quackdcs/async-opcua/async-opcua-nodes/src/method.rs#L105) | HONORED | Modeled as a mandatory attribute. |
