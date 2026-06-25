//! Independent vectors for the limit-alarm evaluation logic (Part 9 §5.8.18–§5.8.20).
//! These pin the threshold + deadband-hysteresis behavior of `LimitEvaluator` and are authored
//! separately from the implementation.

use opcua_server::alarms::{
    ActiveLimits, LimitConfig, LimitDef, LimitEvaluator, LimitLevel, LimitMode, NonExclusiveState,
};

fn d(value: f64, deadband: f64, severity: u16) -> LimitDef {
    LimitDef {
        value,
        deadband,
        severity,
    }
}

/// Run a sequence of values through the evaluator, threading the previous state, and return the
/// `ActiveLimits` observed at each step.
fn run(cfg: &LimitConfig, start: ActiveLimits, values: &[f64]) -> Vec<ActiveLimits> {
    let mut prev = start;
    let mut out = Vec::new();
    for &v in values {
        let outcome = LimitEvaluator::evaluate(v, cfg, &prev);
        prev = outcome.limits;
        out.push(outcome.limits);
    }
    out
}

fn exclusive_high_cfg() -> LimitConfig {
    // High=100 (db 5, sev 400), HighHigh=110 (db 5, sev 700).
    LimitConfig::new(LimitMode::Exclusive)
        .with_high(d(100.0, 5.0, 400))
        .with_high_high(d(110.0, 5.0, 700))
        .build()
        .expect("valid config")
}

#[test]
fn exclusive_high_side_escalates_and_deescalates_with_hysteresis() {
    let cfg = exclusive_high_cfg();
    let seq = run(
        &cfg,
        ActiveLimits::Exclusive(None),
        //   below   High    HighHigh  hold-HH   to-High   hold-High  clear
        &[90.0, 105.0, 115.0, 108.0, 104.0, 97.0, 94.0],
    );
    use LimitLevel::*;
    assert_eq!(
        seq,
        vec![
            ActiveLimits::Exclusive(None),           // 90  : normal
            ActiveLimits::Exclusive(Some(High)),     // 105 : > High
            ActiveLimits::Exclusive(Some(HighHigh)), // 115 : > HighHigh
            ActiveLimits::Exclusive(Some(HighHigh)), // 108 : > 110-5 -> HighHigh holds (deadband)
            ActiveLimits::Exclusive(Some(High)),     // 104 : < 105 clears HH; > 100-5 -> High
            ActiveLimits::Exclusive(Some(High)),     // 97  : > 100-5 -> High holds (deadband)
            ActiveLimits::Exclusive(None),           // 94  : < 95 clears High -> normal
        ]
    );
}

#[test]
fn exclusive_high_severity_tracks_active_band() {
    let cfg = exclusive_high_cfg();
    assert_eq!(
        LimitEvaluator::evaluate(105.0, &cfg, &ActiveLimits::Exclusive(None)).severity,
        400
    );
    assert_eq!(
        LimitEvaluator::evaluate(
            115.0,
            &cfg,
            &ActiveLimits::Exclusive(Some(LimitLevel::High))
        )
        .severity,
        700
    );
    let inactive = LimitEvaluator::evaluate(90.0, &cfg, &ActiveLimits::Exclusive(None));
    assert!(!inactive.active);
}

#[test]
fn exclusive_low_side_escalates_and_deescalates_with_hysteresis() {
    // Low=10 (db 2, sev 400), LowLow=0 (db 2, sev 700).
    let cfg = LimitConfig::new(LimitMode::Exclusive)
        .with_low(d(10.0, 2.0, 400))
        .with_low_low(d(0.0, 2.0, 700))
        .build()
        .expect("valid config");
    use LimitLevel::*;
    let seq = run(
        &cfg,
        ActiveLimits::Exclusive(None),
        &[15.0, 5.0, -5.0, -1.0, 3.0, 11.0, 13.0],
    );
    assert_eq!(
        seq,
        vec![
            ActiveLimits::Exclusive(None),         // 15 : normal
            ActiveLimits::Exclusive(Some(Low)),    // 5  : < Low
            ActiveLimits::Exclusive(Some(LowLow)), // -5 : < LowLow
            ActiveLimits::Exclusive(Some(LowLow)), // -1 : < 0+2 -> LowLow holds
            ActiveLimits::Exclusive(Some(Low)),    // 3  : > 2 clears LL; < 10+2 -> Low
            ActiveLimits::Exclusive(Some(Low)),    // 11 : < 12 -> Low holds (deadband)
            ActiveLimits::Exclusive(None),         // 13 : > 12 clears Low -> normal
        ]
    );
}

#[test]
fn non_exclusive_high_and_highhigh_active_simultaneously() {
    // The defining difference vs exclusive: above HighHigh, BOTH High and HighHigh states are active.
    let cfg = LimitConfig::new(LimitMode::NonExclusive)
        .with_high(d(100.0, 5.0, 400))
        .with_high_high(d(110.0, 5.0, 700))
        .build()
        .expect("valid config");
    let start = ActiveLimits::NonExclusive(NonExclusiveState::default());

    let above_hh = LimitEvaluator::evaluate(115.0, &cfg, &start);
    assert_eq!(
        above_hh.limits,
        ActiveLimits::NonExclusive(NonExclusiveState {
            high_high: true,
            high: true,
            low: false,
            low_low: false,
        })
    );
    assert!(above_hh.active);
    assert_eq!(above_hh.severity, 700, "severity is the max active limit");

    let only_high = LimitEvaluator::evaluate(104.0, &cfg, &above_hh.limits);
    assert_eq!(
        only_high.limits,
        ActiveLimits::NonExclusive(NonExclusiveState {
            high_high: false, // 104 < 110-5=105 clears HH (strict); 104 > 100-5 keeps High
            high: true,
            low: false,
            low_low: false,
        })
    );
    assert_eq!(only_high.severity, 400);
}

#[test]
fn nan_value_holds_previous_state() {
    let cfg = exclusive_high_cfg();
    let prev = ActiveLimits::Exclusive(Some(LimitLevel::High));
    let outcome = LimitEvaluator::evaluate(f64::NAN, &cfg, &prev);
    assert_eq!(
        outcome.limits, prev,
        "a non-finite sample must not change state"
    );
    assert!(outcome.active);
}

#[test]
fn unset_limits_are_never_active() {
    // Only a High limit configured: a very low value does not trip any low limit.
    let cfg = LimitConfig::new(LimitMode::Exclusive)
        .with_high(d(100.0, 0.0, 400))
        .build()
        .expect("valid config");
    let outcome = LimitEvaluator::evaluate(-1000.0, &cfg, &ActiveLimits::Exclusive(None));
    assert_eq!(outcome.limits, ActiveLimits::Exclusive(None));
    assert!(!outcome.active);
}

#[test]
fn inconsistent_limit_ordering_is_rejected() {
    // HighHigh below High violates HighHighLimit >= HighLimit.
    let bad = LimitConfig::new(LimitMode::Exclusive)
        .with_high(d(110.0, 0.0, 400))
        .with_high_high(d(100.0, 0.0, 700))
        .build();
    assert!(
        bad.is_err(),
        "inconsistent ordering must be rejected at build()"
    );
}
