# OPC UA Part 3 Address Space Model Conformance Findings

Scope: OPC UA Part 3 v1.05.06, server-relevant and testable portions requested by the audit prompt.

## Candidate Divergence Summary

1. **Abstract ReferenceTypes can be used by NodeManagement AddReferences.** Part 3 says no Reference of an abstract ReferenceType shall exist; the in-memory AddReferences path only verifies that the supplied ReferenceTypeId is a ReferenceType, then inserts it.
2. **Abstract VariableTypes can be used directly by AddNodes.** Part 3 says no Variable of an abstract VariableType shall exist; the AddNodes path requires a type definition for Variables but does not check whether that type definition is abstract.
3. **Abstract ObjectTypes can be used directly by AddNodes.** Part 3 says no Object of an abstract ObjectType shall exist; the AddNodes path requires a type definition for Objects but does not check whether that type definition is abstract.
4. **Variable ValueRank/ArrayDimensions consistency is not enforced on creation or attribute writes.** Part 3 requires ArrayDimensions cardinality to match the dimensions of the Value and be null for non-arrays; setters and AddNodes builders accept ValueRank and ArrayDimensions independently.
5. **VariableType ValueRank/ArrayDimensions consistency is not enforced on creation or attribute writes.** Part 3 requires ArrayDimensions element count to equal ValueRank and be null when ValueRank <= 0; VariableType setters and constructors accept them independently.

## Base NodeClass Attributes

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| Base nodes expose mandatory NodeId, NodeClass, BrowseName, DisplayName. | §5.2 Table 7, `/tmp/part3.txt:2007` | `async-opcua-nodes/src/base.rs:86` | HONORED | `get_attribute_max_age` returns `NodeClass`, `NodeId`, `BrowseName`, and `DisplayName` for all node classes via the shared `Base`. |
| Base nodes may expose optional WriteMask and UserWriteMask as AttributeWriteMask. | §5.2 Table 7, `/tmp/part3.txt:2015` | `async-opcua-nodes/src/base.rs:95` | HONORED | Optional masks are returned when present; absence maps to `None` and thus BadAttributeIdInvalid at read dispatch. |
| WriteMask/UserWriteMask bits match AttributeWriteMask positions. | §5.2.7-5.2.8, `/tmp/part3.txt:2016` | `async-opcua-types/src/lib.rs:168` | HONORED | `WriteMask` defines the Part 3 attribute bits including `VALUE_FOR_VARIABLE_TYPE` and marks bits 26-31 reserved. |
| Non-Value attribute writes are gated by WriteMask. | §5.2.7-5.2.8, `/tmp/part3.txt:2016` | `async-opcua-server/src/address_space/utils.rs:37` | HONORED | `is_writable` maps each writable attribute to a `WriteMask` bit and rejects missing/unset bits with `BadNotWritable`. |
| UserWriteMask can only further restrict WriteMask. | §5.2.8, `/tmp/part3.txt:2017` | `async-opcua-nodes/src/base.rs:68` | UNCERTAIN | Storage and exposure exist, but the default write gate in `is_writable` uses only `write_mask`; no enforcement tying `user_write_mask` to `write_mask` was found in scoped code. |

## Variable Attributes And Semantics

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| Variable exposes mandatory Value, DataType, ValueRank, AccessLevel, UserAccessLevel, Historizing. | §5.6 Table 13, `/tmp/part3.txt:2695` | `async-opcua-nodes/src/variable.rs:188` | HONORED | `get_attribute_max_age` returns all listed mandatory Variable attributes. |
| Variable exposes optional ArrayDimensions and MinimumSamplingInterval when present. | §5.6 Table 13, `/tmp/part3.txt:2719` | `async-opcua-nodes/src/variable.rs:199` | HONORED | Both optional attributes are returned only when stored. |
| ValueRank values represent scalar, any, scalar-or-one-dimensional, or fixed-dimensional arrays. | §5.6 Table 13, `/tmp/part3.txt:2704` | `async-opcua-types/src/value_rank.rs:7` | HONORED | The `ValueRank` helper documents and bounds the standard ranks; invalid `< -3` can be rejected by `new_checked`. |
| Variable ArrayDimensions element count equals the Value dimensions and is null for non-array values. | §5.6 Table 13, `/tmp/part3.txt:2719` | `async-opcua-nodes/src/variable.rs:237`; `async-opcua-nodes/src/variable.rs:265`; `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:414` | CANDIDATE DIVERGENCE | Spec requires ArrayDimensions consistency/nullness. Code independently accepts `ValueRank` and `ArrayDimensions` through setters and AddNodes build path; no consistency check was found before storing. |
| Variable `DataType` shall be valid and non-null. | §5.6 Table 13, `/tmp/part3.txt:2701` | `async-opcua-nodes/src/variable.rs:586` | HONORED | `Variable::is_valid` requires non-null `data_type`; builder `build/insert` panics unless valid. |
| Value writes validate current user access and data type. | §5.6 Table 13, `/tmp/part3.txt:2735` | `async-opcua-server/src/address_space/utils.rs:30`; `async-opcua-server/src/address_space/utils.rs:274` | HONORED | Value writes require `CURRENT_WRITE` in effective user access level and call data-type validation against the type tree. |
| AccessLevel/UserAccessLevel bit meanings are represented for read/write/history/semantic/status/timestamp. | §5.6 Table 13, `/tmp/part3.txt:2735` | `async-opcua-nodes/src/lib.rs:406` | HONORED | `AccessLevel` defines current read/write, history read/write, semantic change, status write, and timestamp write bits. |
| Effective UserAccessLevel is session-sensitive. | §5.6 Table 13, `/tmp/part3.txt:2742` | `async-opcua-server/src/address_space/utils.rs:322` | HONORED | Reads of `UserAccessLevel` pass stored bits through `effective_user_access_level`. |

## Object And Method Attributes

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| Object exposes mandatory EventNotifier. | §5.5 Table 11, `/tmp/part3.txt:2477` | `async-opcua-nodes/src/object.rs:86` | HONORED | `Object::get_attribute_max_age` returns `EventNotifier` as a byte. |
| Method exposes mandatory Executable and UserExecutable. | §5.7 Table 15, `/tmp/part3.txt:3186` | `async-opcua-nodes/src/method.rs:129` | HONORED | `Method::get_attribute_max_age` returns both mandatory Method attributes. |
| UserExecutable cannot be true when Executable is false. | §5.7 Table 15, `/tmp/part3.txt:3191` | `async-opcua-nodes/src/method.rs:245` | HONORED | `user_executable()` returns `self.executable && self.user_executable`; read dispatch also applies authenticator user-executable checks. |

## VariableType And ObjectType Semantics

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| VariableType exposes mandatory DataType, ValueRank, IsAbstract and optional Value/ArrayDimensions. | §5.6 Table 14, `/tmp/part3.txt:3055` | `async-opcua-nodes/src/variable_type.rs:96` | HONORED | Attribute dispatch returns DataType, IsAbstract, ValueRank, optional Value, and optional ArrayDimensions. |
| VariableType ArrayDimensions count equals ValueRank and is null when ValueRank <= 0. | §5.6 Table 14, `/tmp/part3.txt:3081` | `async-opcua-nodes/src/variable_type.rs:135`; `async-opcua-nodes/src/variable_type.rs:147`; `async-opcua-nodes/src/variable_type.rs:285` | CANDIDATE DIVERGENCE | Spec requires consistency. Code stores `value_rank` and `array_dimensions` independently and accepts writes independently; no validation was found. |
| ObjectType exposes mandatory IsAbstract. | §6 type model / §5.5 type definition context, `/tmp/part3.txt:3133` | `async-opcua-nodes/src/object_type.rs:66` | HONORED | `ObjectType` reads/writes the `IsAbstract` attribute. |
| Abstract VariableTypes cannot be directly instantiated. | §5.6 Table 14, `/tmp/part3.txt:3091` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:49`; `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:109` | CANDIDATE DIVERGENCE | AddNodes requires a type definition for Variables but only carries the provided `type_definition_id` into a `HasTypeDefinition` reference. No check of the target VariableType's `IsAbstract` attribute was found. |
| Abstract ObjectTypes cannot be directly instantiated. | §6 Type Model instance rules, `/tmp/part3.txt:4560` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:49`; `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:109` | CANDIDATE DIVERGENCE | AddNodes requires a type definition for Objects but does not inspect whether the ObjectType is abstract before inserting the Object and `HasTypeDefinition` reference. |
| Instance creation mirrors mandatory/optional InstanceDeclarations per ModellingRules. | §6.4.2, `/tmp/part3.txt:4566` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:101` | UNCERTAIN | The in-memory AddNodes path builds only the requested Object/Variable and attaches parent/type references. No scoped evidence showed creation of child hierarchy from ModellingRules. |

## ReferenceType Rules

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| ReferenceType exposes mandatory IsAbstract and Symmetric. | §5.3 Table 9, `/tmp/part3.txt:2221` | `async-opcua-nodes/src/reference_type.rs:80` | HONORED | Attribute dispatch returns `Symmetric` and `IsAbstract`. |
| Symmetric ReferenceTypes omit InverseName; non-symmetric ReferenceTypes set InverseName. | §5.3.2, `/tmp/part3.txt:2274` | `async-opcua-nodes/src/reference_type.rs:83`; `async-opcua-nodes/src/reference_type.rs:163` | UNCERTAIN | The representation supports omitted or present `InverseName`, but `from_attributes` and setters do not enforce the symmetric/non-symmetric relationship. Generated standard nodes sampled below are correct. |
| Abstract ReferenceTypes cannot be used to create References. | §5.3 Table 9 and §5.3.2, `/tmp/part3.txt:2227`; `/tmp/part3.txt:2267` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:193`; `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:232` | CANDIDATE DIVERGENCE | AddReferences verifies only that `reference_type_id` resolves to `NodeClass::ReferenceType`, then inserts it. No `IsAbstract` check was found, so abstract types such as `References`/`HierarchicalReferences` appear usable directly. |
| Subtypes of concrete ReferenceTypes shall not change the parent's Symmetric value. | §5.3.2, `/tmp/part3.txt:2284` | `async-opcua-nodes/src/reference_type.rs:191`; `async-opcua-nodes/src/type_tree.rs:189` | UNCERTAIN | Code records subtype relationships and stores `symmetric`, but no validator comparing a concrete parent's symmetric value to its subtype was found. |

## Standard ReferenceType Hierarchy

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| `References` is the ReferenceType root and abstract. | §7 hierarchy scope; §5.3 abstract semantics, `/tmp/part3.txt:2267` | `async-opcua-core-namespace/src/generated/nodeset_19.rs:1313` | HONORED | Generated `References` is NodeId `i=31`, `symmetric=true`, `is_abstract=true`, and omits `InverseName`. |
| `NonHierarchicalReferences` is abstract, symmetric, and subtype of `References`. | §7 hierarchy scope; §5.3 symmetric rule, `/tmp/part3.txt:2274` | `async-opcua-core-namespace/src/generated/nodeset_19.rs:1390` | HONORED | Generated NodeId `i=32` has `symmetric=true`, `is_abstract=true`, no `InverseName`, and inverse `HasSubtype` to `i=31`. |
| `HierarchicalReferences` is abstract, non-symmetric, and subtype of `References`. | §7 hierarchy scope; §5.3 non-symmetric rule, `/tmp/part3.txt:2279` | `async-opcua-core-namespace/src/generated/nodeset_19.rs:1471` | HONORED | Generated NodeId `i=33` has `symmetric=false`, `is_abstract=true`, `InverseHierarchicalReferences`, and inverse `HasSubtype` to `i=31`. |
| `HasChild` is abstract, non-symmetric, and subtype of `HierarchicalReferences`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:1501` | HONORED | Generated NodeId `i=34` has `symmetric=false`, `is_abstract=true`, `ChildOf`, and inverse `HasSubtype` to `i=33`. |
| `Organizes` is concrete, non-symmetric, and subtype of `HierarchicalReferences`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:1528` | HONORED | Generated NodeId `i=35` has `symmetric=false`, `is_abstract=false`, `OrganizedBy`, and inverse `HasSubtype` to `i=33`. |
| `HasTypeDefinition` is concrete, non-symmetric, and subtype of `NonHierarchicalReferences`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:2131` | HONORED | Generated NodeId `i=40` has `symmetric=false`, `is_abstract=false`, `TypeDefinitionOf`, and inverse `HasSubtype` to `i=32`. |
| `HasSubtype` is concrete, non-symmetric, and subtype of `HasChild`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:2239` | HONORED | Generated NodeId `i=45` has `symmetric=false`, `is_abstract=false`, `SubtypeOf`, and inverse `HasSubtype` to `i=34`. |
| `HasProperty` is concrete, non-symmetric, and subtype of `Aggregates`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:2266` | HONORED | Generated NodeId `i=46` has `symmetric=false`, `is_abstract=false`, `PropertyOf`, and inverse `HasSubtype` to `i=44`. |
| `HasComponent` is concrete, non-symmetric, and subtype of `Aggregates`. | §7 hierarchy scope | `async-opcua-core-namespace/src/generated/nodeset_19.rs:2293` | HONORED | Generated NodeId `i=47` has `symmetric=false`, `is_abstract=false`, `ComponentOf`, and inverse `HasSubtype` to `i=44`. |

## Address Space Reference Constraints

| Rule | Spec §/line | Impl file:line | Status | Notes |
|---|---:|---|---|---|
| Objects and Variables shall have exactly one HasTypeDefinition reference to the appropriate type class. | §5.5 Table 11, `/tmp/part3.txt:2493`; §5.6 Table 13, `/tmp/part3.txt:2793` | `async-opcua-server/src/node_manager/node_management.rs:49`; `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:109` | UNCERTAIN | AddNodes requires a non-null type definition for Object/Variable and adds one HasTypeDefinition reference, but no scoped evidence showed target node-class validation as ObjectType vs VariableType. |
| Variables shall be Properties or DataVariables of other Nodes, not standalone. | §5.6 Table 13, `/tmp/part3.txt:2683` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:75` | HONORED | AddNodes requires a parent node and inserts the requested parent reference; builder APIs also provide `component_of`/`property_of`. |
| Properties cannot be SourceNode of HasProperty; DataVariables cannot be TargetNode of HasProperty. | §5.6.4, `/tmp/part3.txt:3036` | `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:232` | UNCERTAIN | Generic AddReferences insertion does not appear to classify Variables as Property/DataVariable or enforce these constraints; generated namespace correctness was not exhaustively proven by read-only inspection. |
