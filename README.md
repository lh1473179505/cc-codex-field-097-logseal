# logseal

Offline lab for verifying a hash-chained sealed audit log.

`python -m logseal inspect --log <file>` prints seq, ts, actor, prev_hash
and kid for each entry. `verify` and `admit` must both judge the log with
`logseal.engine.verify_log`. Exit 0 allow, 1 deny, 2 load failure.

Fixture clock is `2026-06-18T09:30:00Z` (unix 1781775000). Rules live in
`docs/verify-rules.md`. Standard library only. No Docker, no network.
