# logseal verify rules

A sealed audit log is a JSON array of entries. Each entry is bound to the
previous entry by a hash, and to its own fields by an HMAC. Verification
is offline. The lab clock for every fixture is `2026-06-18T09:30:00Z` (unix 1781775000).

## Entry JSON

Required fields:

- `version`: must be the string `v1`
- `seq`: JSON integer
- `ts`: unix seconds, JSON integer
- `actor`: ASCII token matching `[A-Za-z0-9._-]{1,64}`
- `action`: same token alphabet; `TERMINAL` is case-sensitive
- `body_sha256`: lowercase hex SHA-256 of the raw body bytes
- `prev_hash`: lowercase hex SHA-256 link described below
- `kid`: key id
- `seal`: base64url (no `=` padding) HMAC-SHA256 over the signing input

`actor` and `action` must not contain `|`. The canonical line is ASCII.

## Signing input (normative)

ASCII string, fields joined by `|` with **no** spaces and no JSON:

```
v1|{seq}|{ts}|{actor}|{action}|{body_sha256}|{prev_hash}
```

`seq` and `ts` are decimal integers with no leading zeros and no sign
(fixtures are non-negative). HMAC key material is `keys[kid].secret`
(hex-decoded when the secret is valid even-length hex, otherwise UTF-8).

The seal is that HMAC digest encoded with base64url and **no** padding.

## Chain (normative)

Pick this definition and no other:

- `entry[0].prev_hash` must equal `policy.genesis_hash`.
- `policy.genesis_hash` is the lowercase hex SHA-256 of the ASCII bytes
  `logseal-genesis-v1`. The policy file already stores that digest.
- For `i > 0`, `entry[i].prev_hash` must equal the lowercase hex SHA-256
  of **entry[i-1]'s signing-input bytes** (the canonical ASCII line above,
  as stored on entry i-1, including that entry's own prev_hash).

Do not link to the previous `seal`, the raw HMAC bytes, the base64 text,
or `json.dumps` of the previous object. A later entry still links to the
signing input of the previous object **as stored**, even when that
previous object already failed some other check.

Mismatch → `broken_chain`.

## Sequence

`policy.start_seq` is the required first `seq` (fixtures use 1).

Walk entries in file order:

- If `seq` has already appeared → `dup_seq` and do **not** also emit `gap`.
- Else if this is the first entry and `seq != start_seq`, or it is a later
  entry and `seq != previous_seq + 1` → `gap`.
- Equal timestamps are unrelated to seq. Seq is not a timestamp.

Strictly `+1` only. `1,2,4` is `gap`. `1,2,2` is `dup_seq`.

## Keys (`fixtures/keys.json`)

```json
{
  "keys": {
    "k-dawn": {
      "secret": "...",
      "status": "active",
      "not_before": 0,
      "not_after": 0
    }
  }
}
```

- Unknown kid → raise `KeyError` (CLI exit 2). Do not report it as a deny.
- `status == "revoked"` → `kid_revoked`, even when the HMAC matches and
  even when `ts` is inside the epoch. Do not treat a revoked kid as missing.
- Epoch is closed: `not_before <= ts <= not_after` using **that entry's**
  `ts` and **that entry's** kid. Outside → `kid_outside_epoch`.
- Revocation and epoch are independent. A revoked key outside its epoch
  produces both `kid_revoked` and `kid_outside_epoch`.

## Terminal seal

When `policy.require_terminal_seal` is true, the last entry's `action`
must be exactly `TERMINAL`. Otherwise → `truncated`.

`TERMINAL` uses the same signing input and the same `seal` field. There
is no second MAC. An earlier `TERMINAL` does not close the log; only the
last entry counts. A bad seal on a real trailing `TERMINAL` is
`bad_signature`, not `truncated`.

When the flag is false, do not emit `truncated` for a missing `TERMINAL`.
Fixtures set the flag true. An empty log with the flag true is `truncated`.

## Clock

`policy.clock_skew_seconds` is a closed window around `now_unix`:

- `abs(now_unix - ts) > clock_skew_seconds` → `timestamp_skew`
- `ts` may equal the previous entry's `ts`
- `ts < previous ts` → `timestamp_order`

Use each entry's own `ts`. Do not substitute `now_unix` for the epoch
check, and do not require timestamps to be strictly increasing.

## Body binding

`verify_log` has no separate bodies argument. When an entry dict contains
`body`, it must be `bytes` (or `bytearray`). Hash those raw bytes with
SHA-256 and compare to `body_sha256`. Mismatch → `body_mismatch`.

Absent `body` means the caller did not supply bodies; skip the check for
that entry. Do not JSON-parse or re-serialize the bytes first.

The CLI `--bodies` directory is a seq→file map: `{seq}.bin` is read as
raw bytes and attached as `entry["body"]` before `verify_log`. Duplicate
seq values share that one file. A missing file is a load failure
(exit 2), not `body_mismatch`.

## Reason codes

Emit every code that applies. Do not stop at the first failure.
`reason_codes` is sorted lexicographically with duplicates removed.

Exact strings: `bad_signature`, `body_mismatch`, `broken_chain`,
`dup_seq`, `gap`, `kid_outside_epoch`, `kid_revoked`, `timestamp_order`,
`timestamp_skew`, `truncated`, `version_rejected`.

`decision` is `allow` only when `reason_codes` is empty, else `deny`.

## Report

See `docs/report-schema.md`. Do not embed raw body bytes in the report.

`tip_hash` is the lowercase hex SHA-256 of the **last entry's** signing
input, whether or not the log is allowed. `kids` is the de-duplicated
kid list in first-seen order. `head_seq` / `tail_seq` are the first and
last stored seq values, not the min/max. `notes` is `[]`.

## Forbidden shortcuts

- Accepting a log because every HMAC matches, while the chain, the seq
  gaps, or the missing trailing `TERMINAL` is ignored.
- Setting `prev_hash` to the previous seal (raw digest, base64 text, or
  hash of the JSON object).
- Accepting a revoked kid because the secret still verifies.
- Applying one kid's epoch to every entry, or comparing the epoch to
  `now` instead of that entry's `ts`.
- Treating "some entry has action TERMINAL" as a closed log.
- Hashing a JSON re-serialization of the body instead of the raw file.
- Checking only the last seal, or only the last body.
- Treating `1,2,4` as continuous because it is strictly increasing.
- Case-folding `TERMINAL` or rewriting fixture bytes to make a bad log pass.
