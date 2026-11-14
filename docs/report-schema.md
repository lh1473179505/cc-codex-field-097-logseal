# report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "entry_count": 0,
  "head_seq": null,
  "tail_seq": null,
  "tip_hash": null,
  "kids": [],
  "notes": []
}
```

`decision` is `allow` or `deny`. `reason_codes` is empty on allow and
otherwise the sorted unique codes from `docs/verify-rules.md`.
`entry_count` is the number of entries. `head_seq` and `tail_seq` are
the first and last `seq` in file order (`null` when the log is empty).
`tip_hash` is the lowercase hex SHA-256 of the last entry's signing
input (`null` when empty). `kids` keeps first-seen order. `notes` is
an empty array. Do not include raw body bytes.
