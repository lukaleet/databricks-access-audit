# Grant Classification

Every Unity Catalog grant found during an audit is classified as one of three sources. The classification determines whether a grant is expected, inherited, or redundant.

---

## Grant sources

### `DIRECT`

The group being audited holds this grant directly. The group name matches the `principal` field in the UC grant.

```
data-engineers  → USE_CATALOG on main   [DIRECT]
```

### `UPSTREAM`

A parent group of the target group holds the grant. The target group inherits the permission through nested group membership.

```
all-data-team (parent of data-engineers) → SELECT on main   [UPSTREAM]
                                           ↳ data-engineers inherits this
```

### `MEMBER_DIRECT`

A user or service principal who is a *member* of the target group holds this grant personally — not via the group. This is a personal grant that bypasses the group.

```
bob@company.com (member of data-engineers) → MODIFY on staging   [MEMBER_DIRECT]
```

`MEMBER_DIRECT` grants are the primary signal for redundancy analysis and cleanup recommendations.

---

## Classification logic

`classify_grant()` in `_classification.py` is the shared function used by all scanners. It receives:

- The grant's principal (who holds it)
- The group name being audited
- Pre-built lookup sets: group members, upstream groups, and the target group itself

It returns a `(GrantSource, inherited_from, member_of_target)` tuple.

`build_member_lookups()` pre-computes these sets from the `GroupNode` tree to avoid redundant iteration during the scan.

---

## Redundancy detection

`RedundancyDetector` compares each `MEMBER_DIRECT` grant against the privileges the group already provides:

| Scenario | `RedundancyLevel` | Recommendation |
|---|---|---|
| Personal grant duplicates all group privileges | `FULL` | Safe to revoke entirely |
| Personal grant has some privileges covered by the group | `PARTIAL` | Revoke only the overlapping privileges |
| Personal grant provides privileges the group doesn't | `NONE` | No action; may be intentional |

`ALL_PRIVILEGES` is expanded to its component privileges before comparison, so a group with `ALL_PRIVILEGES` on a catalog correctly flags members with explicit `SELECT` or `MODIFY` as fully redundant.

---

## Revoke SQL generation

`RevokeScriptGenerator.generate()` produces copy-paste REVOKE SQL from `RedundancyResult` objects:

```sql
-- Full redundancy: bob@company.com on main
REVOKE USE_CATALOG, SELECT ON CATALOG main FROM `bob@company.com`;

-- Partial redundancy: only the covered privileges
REVOKE SELECT ON CATALOG staging FROM `carol@company.com`;
```

The SQL targets the **user or SP directly** — it does not touch the group grant.

---

## Escalation privileges

`detect_escalations()` in `escalation.py` flags two specific privilege types as high-risk:

| Privilege | Risk |
|---|---|
| `ALL_PRIVILEGES` | Identity can read everything, grant access to anyone, and modify schema/table definitions |
| `MANAGE` | Identity can grant or revoke access on the securable to any other principal |

Both are flagged regardless of whether the grant is direct or transitive through group membership.
