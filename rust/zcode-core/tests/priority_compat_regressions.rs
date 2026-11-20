use std::collections::{BTreeMap, HashMap};

use zcode_core::{
    AccountView, SelectionQuery, Selector, StrategyConfig, CHANNEL_FREE, STATUS_ACTIVE,
    STRATEGY_PRIORITY,
};

fn accounts(priorities: &[i64]) -> Vec<AccountView> {
    priorities
        .iter()
        .enumerate()
        .map(|(index, &priority)| AccountView {
            id: index as i64 + 1,
            provider: "zai".into(),
            enabled: true,
            status: STATUS_ACTIVE.into(),
            zcode_jwt: "PUBLIC priority fixture JWT".into(),
            priority,
            ..Default::default()
        })
        .collect()
}

fn priority_selector() -> Selector {
    Selector::new(StrategyConfig {
        strategy: STRATEGY_PRIORITY.into(),
        sticky_enabled: false,
    })
}

#[test]
fn nonpositive_priorities_use_default_100_below_explicit_1_and_50() {
    let accounts = accounts(&[0, -5, 1, 50, 100]);
    let mut selector = priority_selector();
    let mut skip = HashMap::new();
    for expected in [3, 4] {
        for _ in 0..3 {
            let selected = selector
                .select_channel(
                    &accounts,
                    &SelectionQuery {
                        provider: "zai",
                        group: "",
                        skip: &skip,
                        channel: CHANNEL_FREE,
                        now_unix: 1000,
                    },
                )
                .unwrap();
            assert_eq!(
                selected.id, expected,
                "nonpositive priority outranked an explicit tier"
            );
        }
        skip.insert(expected, true);
    }
    let mut counts = BTreeMap::new();
    for _ in 0..6 {
        let selected = selector
            .select_channel(
                &accounts,
                &SelectionQuery {
                    provider: "zai",
                    group: "",
                    skip: &skip,
                    channel: CHANNEL_FREE,
                    now_unix: 1000,
                },
            )
            .unwrap();
        *counts.entry(selected.id).or_insert(0) += 1;
    }
    assert_eq!(
        counts,
        BTreeMap::from([(1, 2), (2, 2), (5, 2)]),
        "nonpositive and explicit 100 must share the same fair tier"
    );
}

#[test]
fn all_nonpositive_priorities_rotate_fairly_in_the_default_tier() {
    let accounts = accounts(&[0, -1, i64::MIN]);
    let mut selector = priority_selector();
    let skip = HashMap::new();
    let query = SelectionQuery {
        provider: "zai",
        group: "",
        skip: &skip,
        channel: CHANNEL_FREE,
        now_unix: 1000,
    };
    let mut counts = BTreeMap::new();
    for _ in 0..9 {
        let selected = selector.select_channel(&accounts, &query).unwrap();
        *counts.entry(selected.id).or_insert(0) += 1;
    }
    assert_eq!(
        counts,
        BTreeMap::from([(1, 3), (2, 3), (3, 3)]),
        "different nonpositive values must not starve peers"
    );
}
