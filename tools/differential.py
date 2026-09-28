#!/usr/bin/env python3
"""Direct engine-parity harness: both implementations, same inputs, byte-compared verdicts.

The corpus cross-check's oracle is MANIFEST.json, so engine agreement there is transitive
through the shared expectations — both engines can hold the same wrong assumption and stay
green, and an input the corpus does not carry is never compared at all. That is how an
explicit-null `record_commits` forked the two engines (Python `is None` vs TS `=== undefined`)
while every run stayed green. Reported as a limit of the corpus cross-check by @Rul1an
(issue #4, second report).

This harness is the non-transitive control: every corpus vector PLUS a deterministic
off-corpus mutation battery at fork-prone keys (explicit nulls, declared/derivable conflicts,
containers of the wrong shape; since v0.5.0 also the chain kinds — dropped, renumbered,
swapped, truncated and (v0.5.2) duplicated records, an off-by-one head, and every plausible
wrong accumulator fold at `head.acc`), run through BOTH engines, verdict and reason-code
compared directly.
Any divergence exits non-zero and prints the offending input.

Run:  npm i viem  (repo root), then  python3 tools/differential.py
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from verify import CHECKS, digest_of, chain_link_digest, chain_acc_step, ACC_GENESIS  # noqa: E402
from keccak import keccak256  # noqa: E402


def py_verdict(kind, inp):
    """Mirror the Python runner's convention: an exception is a malformed input, not a crash."""
    try:
        verdict, reason, _detail = CHECKS[kind](inp)
        return [verdict, reason]
    except Exception:
        return ["malformed", None]


def _chain_rows(inp):
    """The chain rows of a chain_set / chain_commitment input in seq order, or None when the
    input is not shaped for a fold (the fold-variant mutations need parseable digests and
    integer seqs; a shape-broken input is already covered by the shape mutations)."""
    records = inp.get("records")
    if not isinstance(records, list) or not records:
        return None
    rows = []
    for r in records:
        if not isinstance(r, dict) or not isinstance(r.get("seq"), int) or isinstance(r.get("seq"), bool):
            return None
        if not 1 <= r["seq"] < 2**64:
            return None
        a = r.get("artifact_digest")
        if not isinstance(a, str) or len(a) != 66 or not a.startswith("0x"):
            return None
        try:
            bytes.fromhex(a[2:])
        except ValueError:
            return None
        rows.append((r["seq"], a.lower()))
    return sorted(rows)


def _fold(rows, seed, step):
    """Fold `step(acc, link_or_artifact)` over the presented rows with prev = previous artifact."""
    acc, prev = seed, None
    for seq, artifact in rows:
        acc = step(acc, chain_link_digest(artifact, prev, seq), artifact)
        prev = artifact
    return acc


def mutations(kind, inp):
    """Deterministic off-corpus battery. Every case is representable JSON — the absent-key
    case (the only honest 'undefined') is simply a case where the key is not added.
    Yields (tag, kind, input): a mutation may re-target the input at a sibling kind (the
    chain_set → chain_commitment promotions) so the two predicates are compared over the
    same bytes."""
    out = []

    def with_key(key, value, tag):
        m = json.loads(json.dumps(inp))
        m[key] = value
        out.append((tag, kind, m))

    def without_key(key, tag):
        if key in inp:
            m = json.loads(json.dumps(inp))
            del m[key]
            out.append((tag, kind, m))

    if kind in ("chain_set", "chain_commitment"):
        # First off-corpus coverage for the chain kinds (v0.5.0). The structural shape
        # mutations run under BOTH kinds — chain_commitment propagates chain_set's verdict
        # unchanged, so any fork there shows up twice — and the accumulator variants pin
        # every plausible wrong fold at the one key the accumulator lives on. For chain_set
        # inputs the accumulator cases are promoted to chain_commitment, so the same bytes
        # are compared under both predicates.
        acc_kind = "chain_commitment"

        def with_head(key, value, tag, target=kind):
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("head"), dict):
                m["head"][key] = value
                out.append((tag, target, m))

        def with_records(fn, tag):
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("records"), list) and all(isinstance(r, dict) for r in m["records"]):
                fn(m["records"])
                out.append((tag, kind, m))

        def _drop_middle(records):
            if len(records) >= 2:
                del records[len(records) // 2]

        def _renumber_last(records):
            if records and isinstance(records[-1].get("seq"), int):
                records[-1]["seq"] += 1

        def _swap_2_3(records):
            if len(records) >= 3:
                records[1], records[2] = records[2], records[1]
                records[1]["seq"], records[2]["seq"] = records[2]["seq"], records[1]["seq"]

        def _truncate(records):
            if records:
                del records[-1]

        def _float_seq_first(records):
            if records and isinstance(records[0].get("seq"), int):
                records[0]["seq"] = float(records[0]["seq"])  # wire token `1.0` (v0.5.1, B25)

        def _duplicate_middle(records):
            # v0.5.2: a second, different record at an occupied seq, inserted beside the
            # original. Both engines must return the same verdict and reason whatever order
            # their sort leaves the two in.
            if records:
                dup = dict(records[len(records) // 2])
                dup["artifact_digest"] = "0x" + "ee" * 32
                records.insert(len(records) // 2 + 1, dup)

        with_records(_float_seq_first, "records[0].seq=float-token")
        with_records(_duplicate_middle, "records=duplicated-middle")
        if isinstance(inp.get("head"), dict) and isinstance(inp["head"].get("seq"), int):
            with_head("seq", float(inp["head"]["seq"]), "head.seq=float-token")
            with_head("seq", float(inp["head"]["seq"]), "head.seq=float-token@commitment", acc_kind)
        with_records(_drop_middle, "records=dropped-middle")
        with_records(_renumber_last, "records=renumbered-last")
        with_records(_swap_2_3, "records=swapped-2-3")
        with_records(_truncate, "records=truncated-under-full-head")
        if isinstance(inp.get("head"), dict) and isinstance(inp["head"].get("seq"), int):
            with_head("seq", inp["head"]["seq"] + 1, "head.seq=off-by-one")
        with_head("acc", None, "head.acc=null", acc_kind)
        with_head("acc", "0x1234", "head.acc=malformed", acc_kind)
        m = json.loads(json.dumps(inp))
        if isinstance(m.get("head"), dict):
            m["head"].pop("acc", None)
            out.append(("head.acc-absent", acc_kind, m))
        rows = _chain_rows(inp)
        if rows is not None:
            true_acc = _fold(rows, ACC_GENESIS, lambda acc, link, _a: chain_acc_step(acc, link))
            with_head("acc", true_acc, "head.acc=true-fold", acc_kind)
            with_head("acc", "0x" + true_acc[2:].upper(), "head.acc=true-fold-uppercase", acc_kind)
            with_head("acc", "  " + true_acc + "  ", "head.acc=true-fold-padded", acc_kind)
            with_head("acc", _fold(rows, "0x" + "00" * 32, lambda acc, link, _a: chain_acc_step(acc, link)),
                      "head.acc=zero-seed-fold", acc_kind)
            with_head("acc", _fold(rows, ACC_GENESIS, lambda acc, link, _a: chain_acc_step(link, acc)),
                      "head.acc=link-then-acc-fold", acc_kind)
            with_head("acc", _fold(rows, ACC_GENESIS, lambda acc, _l, artifact: chain_acc_step(acc, artifact)),
                      "head.acc=artifact-fold", acc_kind)
            with_head("acc", chain_acc_step(ACC_GENESIS, chain_link_digest(rows[-1][1], rows[-2][1] if len(rows) > 1 else None, rows[-1][0])),
                      "head.acc=last-link-only", acc_kind)
            with_head("acc", "0x" + keccak256(b"tersign-chain-commitment-v1").hex(), "head.acc=seed-only", acc_kind)
            # The true fold over a truncated presentation under the full head: completeness must
            # win before the accumulator is even consulted, in both engines.
            m = json.loads(json.dumps(inp))
            if isinstance(m.get("head"), dict) and len(m.get("records") or []) > 1:
                del m["records"][-1]
                m["head"]["acc"] = _fold(rows[:-1], ACC_GENESIS, lambda acc, link, _a: chain_acc_step(acc, link))
                out.append(("records=truncated+head.acc=fold-of-truncation", acc_kind, m))

    # Fork-prone key 1: record_commits — presence must reject identically whatever it holds.
    with_key("record_commits", ["settlement"], "record_commits=list")
    with_key("record_commits", None, "record_commits=null")
    if kind == "independence_claim":
        with_key("record_commits", "settlement", "record_commits=string")
        with_key("record_commits", [], "record_commits=empty-list")
        # Fork-prone key 2: settlement_result container shape — isinstance(dict) vs
        # typeof 'object' disagree on arrays and null unless both engines exclude them.
        with_key("settlement_result", [], "settlement_result=array")
        with_key("settlement_result", None, "settlement_result=null")
        without_key("settlement_result", "settlement_result-absent")
        # Fork-prone key 3: covers — null-vs-absent and empty-container readings must
        # stay parallel for the same reason record_commits' did not.
        with_key("covers", None, "covers=null")
        with_key("covers", [], "covers=empty-list")
        without_key("covers", "covers-absent")
        # Fork-prone key 4: the delivery pair — key PRESENCE decides evaluability, the
        # recompute decides commitment. null-vs-absent, container shape, digest case, and a
        # non-ASCII suffix (utf8 in Python `.encode` vs viem `stringToHex`) must read
        # identically in both engines.
        with_key("deliverable_bytes", None, "deliverable_bytes=null")
        with_key("deliverable_bytes", [], "deliverable_bytes=array")
        with_key("deliverable_bytes", {"v": 1}, "deliverable_bytes=object")
        without_key("deliverable_bytes", "deliverable_bytes-absent")
        with_key("deliverable_digest", None, "deliverable_digest=null")
        with_key("deliverable_digest", "0x1234", "deliverable_digest=malformed")
        with_key("deliverable_digest", "0x" + "00" * 32, "deliverable_digest=mismatch")
        without_key("deliverable_digest", "deliverable_digest-absent")
        if isinstance(inp.get("deliverable_digest"), str):
            with_key("deliverable_digest", "0x" + inp["deliverable_digest"][2:].upper(), "deliverable_digest=uppercase")
            with_key("deliverable_digest", "  " + inp["deliverable_digest"] + "  ", "deliverable_digest=padded")
        if isinstance(inp.get("deliverable_bytes"), str):
            with_key("deliverable_bytes", inp["deliverable_bytes"] + " ", "deliverable_bytes=trailing-space")
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\u00e9", "deliverable_bytes=non-ascii-suffix")
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\U0001F600", "deliverable_bytes=astral-suffix")
            # Valid JSON, no UTF-8 form: the one string both engines must refuse to hash.
            with_key("deliverable_bytes", inp["deliverable_bytes"] + "\ud800", "deliverable_bytes=lone-surrogate")
        if "deliverable_bytes" not in inp:
            # A settlement-shaped record that grows a digest-only delivery key: both engines
            # must read it as presented-and-empty, never as unevaluable.
            with_key("deliverable_digest", "0x" + "00" * 32, "deliverable_digest-only")
        # Both commitment sources at once: composition order must not leak into the verdict.
        m = json.loads(json.dumps(inp))
        m.setdefault("settlement_result", {"success": True, "transaction": "0xab", "network": "eip155:8453"})
        m["covers"] = ["settlement", "delivery"]
        out.append(("covers=settlement+delivery", kind, m))
    if kind == "decision_evidence_binding":
        # Binding-specific fail-closed battery. These cases are intentionally outside the
        # shared manifest oracle so Python/TS shape readings are compared directly.
        without_key("decision_evidence", "decision_evidence=absent")
        with_key("decision_evidence", None, "decision_evidence=null")
        with_key("decision_evidence", [], "decision_evidence=array")
        with_key("decision_evidence", "not-an-object", "decision_evidence=string")
        for tag, record in (
            ("record=absent", None),
            ("record=null", None),
            ("record=array", []),
            ("record=empty-object", {}),
        ):
            m = json.loads(json.dumps(inp))
            if tag == "record=absent":
                m.pop("record", None)
            else:
                m["record"] = record
            out.append((tag, kind, m))
        if isinstance(inp.get("record"), dict):
            for tag, digest in (
                ("commitment=null", None),
                ("commitment=malformed", "0x1234"),
                ("commitment=mismatch", "0x" + "00" * 32),
            ):
                m = json.loads(json.dumps(inp))
                m["record"]["decisionEvidenceDigest"] = digest
                out.append((tag, kind, m))
        if isinstance(inp.get("decision_evidence"), dict):
            m = json.loads(json.dumps(inp))
            m["decision_evidence"].setdefault("policy", {})["version"] = "substituted"
            out.append(("decision_evidence=policy-substitution", kind, m))
    if kind == "offer_binding":
        # Regression for key absence versus an explicit JSON null. Python previously used
        # indexing while JS canonicalization received undefined; a refactor to `.get()` can
        # accidentally turn absence into null and accept a digest of canonical `null`.
        m = json.loads(json.dumps(inp))
        m.pop("offer", None)
        m.setdefault("receipt", {})["offerDigest"] = digest_of(None)
        out.append(("offer=absent-with-null-commitment", kind, m))
    return out


def main():
    vectors_dir = os.path.join(ROOT, "vectors")
    cases = []
    for fname in sorted(os.listdir(vectors_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(vectors_dir, fname)) as f:
            vector = json.load(f)
        kind, inp = vector["kind"], vector["input"]
        cases.append({"label": f"{fname}", "kind": kind, "input": inp})
        for tag, target_kind, mutated in mutations(kind, inp):
            label = f"{fname}::{tag}" if target_kind == kind else f"{fname}::{tag}@{target_kind}"
            cases.append({"label": label, "kind": target_kind, "input": mutated})

    py_results = [py_verdict(c["kind"], c["input"]) for c in cases]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(cases, tf)
        tmp_path = tf.name
    try:
        proc = subprocess.run(
            ["node", os.path.join(ROOT, "tools", "differential_helper.mjs"), tmp_path],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("differential: node helper failed:", proc.stderr.strip(), file=sys.stderr)
            return 1
        ts_results = json.loads(proc.stdout)
    finally:
        os.unlink(tmp_path)

    if len(ts_results) != len(cases):
        print(f"differential: case count mismatch ({len(ts_results)} vs {len(cases)})", file=sys.stderr)
        return 1

    diverged = 0
    for case, py_r, ts_r in zip(cases, py_results, ts_results):
        if py_r != ts_r:
            diverged += 1
            print(f"DIVERGE {case['label']}: PY {py_r} vs TS {ts_r}")
            print(f"        input: {json.dumps(case['input'])[:200]}")
    print(
        f"DIFFERENTIAL {'OK' if diverged == 0 else 'FAILED'}: "
        f"{len(cases)} cases ({sum(1 for c in cases if '::' in c['label'])} off-corpus), "
        f"{diverged} divergence(s)"
    )
    return 0 if diverged == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
