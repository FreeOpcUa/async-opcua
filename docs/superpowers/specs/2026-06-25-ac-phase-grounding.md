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
