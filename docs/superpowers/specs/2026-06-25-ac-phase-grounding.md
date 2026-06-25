# A&C completion — phase grounding (OPC 10000-9, via opc-ua-reference MCP 2026-06-25)

## AC1 (done): DiscreteAlarm/OffNormal
DiscreteAlarmType 10523 (abstract), OffNormalAlarmType 10637, TripAlarmType 10751,
OffNormalAlarmType_NormalState 11158. Active when value != NormalState.

## AC2: Shelving + Suppression
- ShelvedStateMachineType 2929 (subtype FiniteStateMachineType). States Unshelved/OneShotShelved/
  TimedShelved. Methods: Unshelve 2947, OneShotShelve 2948, TimedShelve 2949 (TimedShelve takes a
  ShelvingTime Duration arg). UnshelveTime 9115 = remaining ms until auto-unshelve (init from
  ShelvingTime for TimedShelve). All transitions among the 3 states supported.
- On AlarmConditionType: ShelvingState 9178 (Object = the ShelvedStateMachine instance),
  SuppressedState 9169 (TwoStateVariable, system/server suppress), OutOfServiceState 16371
  (maintenance suppress), SuppressedOrShelved 9215 (computed = Suppressed || OutOfService ||
  Shelved!=Unshelved). §5.8.2: these three together suppress alarms on display systems.
- Gating: SuppressedOrShelved=true => alarm not reported on displays (but still tracked). Method
  status codes: BadConditionAlreadyShelved / BadConditionNotShelved / BadShelvingTimeOutOfRange.
- Auto-unshelve timer for TimedShelved: lazily evaluate (on access/update, transition to Unshelved
  if UnshelveTime elapsed) is an acceptable simplification (ponytail) vs a dedicated timer.

## AC3: Branching (§5.5.x)
Condition can keep multiple BranchId branches (prior unacked states) alive; current = BranchId null.
Each branch independently acked/confirmed by (ConditionId, EventId). ConditionRefresh replays all
retained branches. (Ground §5.5.2 fully when starting AC3.)

## AC4: AnalogItem/EURange
AnalogItemType EURange property (i=?) -> limit alarm sources its range from the AnalogItem instead of
hard-coded config. (Ground AnalogItemType_EURange id when starting AC4.)

## AC3 branching — DETAIL (OPC 10000-9, grounded 2026-06-25)
- ConditionType has `BranchId` (NodeId Property, Mandatory). Trunk/current state => BranchId NULL.
  A ConditionBranch preserves a PREVIOUS state independently of the current state; unique BranchId
  per active branch (§5.5.2/5.5.3/§4.2). Server emits separate Event Notifications per branch.
- Creation trigger (canonical, §B.1.3 Table B.2): a condition goes Active(unacked) -> Inactive while
  still unacked -> the server SPAWNS a branch capturing the (prior Active, unacked) state with a new
  BranchId + EventId, so the operator can still Acknowledge that activation; the trunk follows the new
  (Inactive) state. Branch Retain stays true until it is acked+confirmed, then it is dropped.
- Acknowledge/Confirm (§5.7.3/5.7.4) by EventId: if EventId matches a branch, that branch is acked/
  confirmed and reported with its BranchId + values; else the trunk. A branch fully acked+confirmed+
  inactive => Retain=false => removed.
- ConditionRefresh replays the trunk + every retained branch (each as its own event with its BranchId).
- ORACLE: §B.1.3 Table B.2 (EventId/BranchId/Active/Acked/Confirmed/Retain rows).
- Design (Claude-owned): a Branch snapshot { branch_id, event_id, active, acked, confirmed, retain,
  severity, message } stored per-condition (registry/condition); branch creation in the shared alarm
  update path; ack/confirm-by-EventId routes to branch or trunk; refresh iterates trunk+branches.
