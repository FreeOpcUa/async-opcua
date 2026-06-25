use std::{
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use crate::utils::ChannelNotifications;

use super::utils::setup;
use opcua::{
    server::{
        address_space::MethodBuilder,
        node_manager::{typed_method, typed_method_with_context, RequestContext},
    },
    types::{
        AttributeId, CallMethodRequest, DataTypeId, NodeId, ObjectId, StatusCode, Variant,
        VariantTypeId,
    },
};
use opcua_types::{
    MonitoredItemCreateRequest, MonitoringParameters, ReadValueId, TimestampsToReturn, VariableId,
    VariantScalarTypeId,
};

#[tokio::test]
async fn call_trivial() {
    let (_tester, nm, session) = setup().await;
    let called = Arc::new(AtomicU64::new(0));

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "TestMethod1", "TestMethod1")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[])
            .output_args(&mut *sp, &output_id, &[])
            .insert(&mut *sp);
    }

    let called_ref = called.clone();
    nm.inner().add_method_cb(id.clone(), move |_| {
        called_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(vec![])
    });

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: None,
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::Good);
    assert_eq!(1, called.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn call_args() {
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "MethodAdd", "MethodAdd")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(
                &mut *sp,
                &input_id,
                &[
                    ("Lhs", DataTypeId::Int64).into(),
                    ("Rhs", DataTypeId::Int64).into(),
                ],
            )
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }

    nm.inner().add_method_cb(id.clone(), |args| {
        let Some(Variant::Int64(lhs)) = args
            .first()
            .map(|a| a.cast(VariantTypeId::Scalar(VariantScalarTypeId::Int64)))
        else {
            return Err(StatusCode::BadInvalidArgument);
        };
        let Some(Variant::Int64(rhs)) = args
            .get(1)
            .map(|a| a.cast(VariantTypeId::Scalar(VariantScalarTypeId::Int64)))
        else {
            return Err(StatusCode::BadInvalidArgument);
        };

        Ok(vec![Variant::Int64(lhs + rhs)])
    });

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(3), Variant::Int64(2)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::Good);
    let outputs = r.output_arguments.unwrap().clone();
    assert_eq!(1, outputs.len());
    let Variant::Int64(v) = outputs[0] else {
        panic!("Wrong output type");
    };
    assert_eq!(v, 5);

    // Call with wrong args
    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::String("foo".into()), Variant::Int64(2)]),
        })
        .await
        .unwrap();

    assert_eq!(r.status_code, StatusCode::BadInvalidArgument);
}

#[tokio::test]
async fn call_fail() {
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "MethodAdd", "MethodAdd")
            .user_executable(false)
            .component_of(ObjectId::ObjectsFolder)
            .input_args(
                &mut *sp,
                &input_id,
                &[
                    ("Lhs", DataTypeId::Int64).into(),
                    ("Rhs", DataTypeId::Int64).into(),
                ],
            )
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }

    nm.inner().add_method_cb(id.clone(), |args| {
        let Some(Variant::Int64(lhs)) = args.first().map(|a| a.cast(VariantScalarTypeId::Int64))
        else {
            return Err(StatusCode::BadInvalidArgument);
        };
        let Some(Variant::Int64(rhs)) = args.get(1).map(|a| a.cast(VariantScalarTypeId::Int64))
        else {
            return Err(StatusCode::BadInvalidArgument);
        };

        Ok(vec![Variant::Int64(lhs + rhs)])
    });

    // Call method that doesn't exist
    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: NodeId::new(2, 100),
            input_arguments: Some(vec![Variant::Int64(3), Variant::Int64(2)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadMethodInvalid);

    // Call on wrong object
    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::Server.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(3), Variant::Int64(2)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadMethodInvalid);

    // Call without permission
    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(3), Variant::Int64(2)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadUserAccessDenied);

    {
        let sp = nm.address_space().write();
        sp.find_mut(&id)
            .unwrap()
            .as_mut_node()
            .set_attribute(AttributeId::UserExecutable, Variant::Boolean(true))
            .unwrap();
    }

    // Call with too many arguments
    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![
                Variant::Int64(3),
                Variant::Int64(2),
                Variant::Int64(3),
            ]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadTooManyArguments);
}

#[tokio::test]
async fn call_limits() {
    let (tester, _nm, session) = setup().await;

    let limit = tester
        .handle
        .info()
        .config
        .limits
        .operational
        .max_nodes_per_method_call;

    // Call none
    let e = session.call(Vec::new()).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::BadNothingToDo);

    // Call too many
    let e = session
        .call(
            (0..(limit + 1))
                .map(|i| CallMethodRequest {
                    object_id: ObjectId::ObjectsFolder.into(),
                    method_id: NodeId::new(2, i as u32),
                    input_arguments: None,
                })
                .collect(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.status(), StatusCode::BadTooManyOperations);
}

#[tokio::test]
async fn call_get_monitored_items() {
    let (_tester, _nm, session) = setup().await;

    let (notifs, _data, _) = ChannelNotifications::new();

    // Create a subscription
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();

    // Create a monitored item on that subscription
    session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: VariableId::Server_ServerStatus_State.into(),
                    attribute_id: AttributeId::Value as u32,
                    ..Default::default()
                },
                monitoring_mode: opcua::types::MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    client_handle: 15,
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();

    let (ids, handles) = session.call_get_monitored_items(sub_id).await.unwrap();

    assert_eq!(ids.len(), 1);
    assert_eq!(handles.len(), 1);
    assert_eq!(15, handles[0]);
}

// --- Feature 021: typed method-call framework, end-to-end through the Call service ---

/// A method registered via the typed framework is callable end-to-end and returns the right
/// typed output (SC-003) — no manual Variant indexing/marshaling in the handler.
#[tokio::test]
async fn call_typed_method_roundtrip() {
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "TypedAdd", "TypedAdd")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(
                &mut *sp,
                &input_id,
                &[
                    ("Lhs", DataTypeId::Int64).into(),
                    ("Rhs", DataTypeId::Int64).into(),
                ],
            )
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }

    // Registered through the typed adapter — the closure sees decoded i64s and returns a typed tuple.
    nm.inner().add_method_cb(
        id.clone(),
        typed_method(|a: i64, b: i64| -> Result<(i64,), StatusCode> { Ok((a + b,)) }),
    );

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(3), Variant::Int64(4)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::Good);
    assert_eq!(r.output_arguments.unwrap(), vec![Variant::Int64(7)]);
}

/// A typed handler's own error return propagates as the Call operation status, end-to-end.
#[tokio::test]
async fn call_typed_method_user_error_propagates() {
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "TypedDouble", "TypedDouble")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[("X", DataTypeId::Int64).into()])
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }

    nm.inner().add_method_cb(
        id.clone(),
        typed_method(|x: i64| -> Result<(i64,), StatusCode> {
            if x < 0 {
                Err(StatusCode::BadOutOfRange)
            } else {
                Ok((x * 2,))
            }
        }),
    );

    // Valid input -> Good + correct output.
    let ok = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(5)]),
        })
        .await
        .unwrap();
    assert_eq!(ok.status_code, StatusCode::Good);
    assert_eq!(ok.output_arguments.unwrap(), vec![Variant::Int64(10)]);

    // Handler's own error surfaces as the Call status.
    let err = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(-1)]),
        })
        .await
        .unwrap();
    assert_eq!(err.status_code, StatusCode::BadOutOfRange);
}

/// US3: a context-aware typed method receives both the `RequestContext` and decoded typed args, and
/// runs end-to-end through the Call service. The handler reads the context (session id) and the typed
/// argument, proving both are threaded correctly.
#[tokio::test]
async fn call_typed_method_with_context() {
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "TypedCtx", "TypedCtx")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[("Addend", DataTypeId::Int64).into()])
            .output_args(
                &mut *sp,
                &output_id,
                &[("SessionPlusAddend", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }

    // Context-aware typed handler: reads the session id from the context AND a decoded i64 argument.
    nm.inner().add_method_cb_with_context(
        id.clone(),
        typed_method_with_context(
            |ctx: &RequestContext, addend: i64| -> Result<(i64,), StatusCode> {
                Ok((ctx.session_id as i64 + addend,))
            },
        ),
    );

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(1000)]),
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::Good);
    let outputs = r.output_arguments.unwrap();
    assert_eq!(outputs.len(), 1);
    let Variant::Int64(v) = outputs[0] else {
        panic!("wrong output type");
    };
    // A real activated session has a positive numeric id, so the context was threaded through
    // (output = session_id + 1000 > 1000) and the typed argument decoded correctly.
    assert!(
        v > 1000,
        "context session id should be threaded through, got {v}"
    );
}

#[tokio::test]
async fn call_non_executable_method_is_bad_not_executable() {
    // P4-METHOD-01 — OPC UA Part 4 §5.12 Table 61: when the Executable attribute does not allow
    // execution, Call returns Bad_NotExecutable. This is distinct from Bad_UserAccessDenied (the
    // UserExecutable / permission case). Anchored to the spec.
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "NonExec", "NonExec")
            .executable(false)
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[])
            .output_args(&mut *sp, &output_id, &[])
            .insert(&mut *sp);
    }
    nm.inner().add_method_cb(id.clone(), move |_| Ok(vec![]));

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: None,
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadNotExecutable);
}

#[tokio::test]
async fn failed_method_call_has_no_output_arguments() {
    // P4-METHOD-02 — OPC UA Part 4 §5.12 (line 3953): outputArguments shall be empty when the call
    // statusCode severity is Bad. A method that fails validation must not return output arguments.
    let (_tester, nm, session) = setup().await;
    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "NoPerm", "NoPerm")
            .user_executable(false)
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[])
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }
    nm.inner()
        .add_method_cb(id.clone(), |_| Ok(vec![Variant::Int64(1)]));

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: None,
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadUserAccessDenied);
    assert!(
        r.output_arguments.is_none(),
        "outputArguments must be empty when the call status is Bad, got {:?}",
        r.output_arguments
    );
}

#[tokio::test]
async fn call_with_missing_arguments() {
    // Part 4 §5.12.2: a Call that omits a declared input argument returns Bad_ArgumentsMissing.
    // The callback ignores its arguments, so the status reflects the server's own validation.
    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "MethodAdd2", "MethodAdd2")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(
                &mut *sp,
                &input_id,
                &[
                    ("Lhs", DataTypeId::Int64).into(),
                    ("Rhs", DataTypeId::Int64).into(),
                ],
            )
            .output_args(
                &mut *sp,
                &output_id,
                &[("Result", DataTypeId::Int64).into()],
            )
            .insert(&mut *sp);
    }
    nm.inner()
        .add_method_cb(id.clone(), |_args| Ok(vec![Variant::Int64(0)]));

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: Some(vec![Variant::Int64(3)]), // only 1 of the 2 declared args
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::BadArgumentsMissing);
}

/// Part 4/3 auditing: a method Call emits an AuditUpdateMethodEventType (i=2127) from the Server node,
/// recording the called MethodId.
#[tokio::test]
async fn method_call_emits_audit_event() {
    use opcua::types::{
        EventFilter, ExtensionObject, MonitoringMode, NumericRange, QualifiedName,
        SimpleAttributeOperand,
    };

    let (_tester, nm, session) = setup().await;

    let id = nm.inner().next_node_id();
    let input_id = nm.inner().next_node_id();
    let output_id = nm.inner().next_node_id();
    {
        let mut sp = nm.address_space().write();
        MethodBuilder::new(&id, "AuditMethod", "AuditMethod")
            .component_of(ObjectId::ObjectsFolder)
            .input_args(&mut *sp, &input_id, &[])
            .output_args(&mut *sp, &output_id, &[])
            .insert(&mut *sp);
    }
    nm.inner().add_method_cb(id.clone(), move |_| Ok(vec![]));

    // Subscribe to Server events.
    let (notifs, _, mut events) = ChannelNotifications::new();
    let sub_id = session
        .create_subscription(Duration::from_millis(100), 100, 20, 1000, 0, true, notifs)
        .await
        .unwrap();
    let select = vec![
        SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2041), // BaseEventType
            browse_path: Some(vec![QualifiedName::new(0, "EventType")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
        SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, 2127), // AuditUpdateMethodEventType
            browse_path: Some(vec![QualifiedName::new(0, "MethodId")]),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
        },
    ];
    let res = session
        .create_monitored_items(
            sub_id,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest {
                item_to_monitor: ReadValueId {
                    node_id: ObjectId::Server.into(),
                    attribute_id: AttributeId::EventNotifier as u32,
                    ..Default::default()
                },
                monitoring_mode: MonitoringMode::Reporting,
                requested_parameters: MonitoringParameters {
                    sampling_interval: 0.0,
                    queue_size: 10,
                    discard_oldest: true,
                    filter: ExtensionObject::new(EventFilter {
                        select_clauses: Some(select),
                        where_clause: Default::default(),
                    }),
                    ..Default::default()
                },
            }],
        )
        .await
        .unwrap();
    assert_eq!(res[0].result.status_code, StatusCode::Good);

    let r = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: id.clone(),
            input_arguments: None,
        })
        .await
        .unwrap();
    assert_eq!(r.status_code, StatusCode::Good);

    // Find the AuditUpdateMethodEventType event carrying the called MethodId.
    let audit_type = Variant::from(NodeId::new(0, 2127));
    let mut found = false;
    for _ in 0..5 {
        let Ok(Some((_h, v))) = tokio::time::timeout(Duration::from_secs(3), events.recv()).await
        else {
            break;
        };
        let fields = v.unwrap();
        if fields[0] == audit_type {
            assert_eq!(
                fields[1],
                Variant::from(id.clone()),
                "audit must carry the MethodId"
            );
            found = true;
            break;
        }
    }
    assert!(
        found,
        "an AuditUpdateMethodEventType must be delivered after a method Call"
    );
}
