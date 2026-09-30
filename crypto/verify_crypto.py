#!/usr/bin/env python3
"""Crypto-profile runner (counter-signature recovery over chain links). Stdlib only + the suite's keccak.py.
    python3 crypto/verify_crypto.py             -> every vector named in crypto/MANIFEST.json; exit 0 iff every verdict and
                                                   reject reason matches AND the set is well formed (see manifest_problems)
    python3 crypto/verify_crypto.py --mutants   -> each plausible broken verifier must be killed by its named vector
Check, per vector, in this order:
 1. every required field is present (artifact_digest, seq, countersignature, ledger_signer), else malformed_input;
 2. field domain (malformed_input): artifact_digest, prev_digest (when present) and ledger_signer are normalized as the core's
    identifier_normalization does -- strip leading/trailing Unicode White_Space characters (exactly the core's set) and lowercase --
    then must be exactly 0x + 64 hex (digests) / 0x + 40 hex (signer); seq is an integer token in [1, 2**53 - 1] (not bool/str/float);
    an absent prev_digest (key omitted or null) means genesis, 32 zero bytes;
 3. link_version: absent means 1; any other value than the integer 1 rejects as unsupported_link_version;
 4. link = keccak256(artifact_digest || prev_digest or 32 zero bytes || uint64_be(seq))  [the core chain_link, link_version 1];
 5. countersignature is matched whole, unnormalized: exactly "0x" + 130 hex digits (no whitespace, no "0X"), v in {27, 28},
    else malformed_signature;
 6. low-s (EIP-2, s <= n/2) on the signature bytes BEFORE recovery, else non_canonical_s (rejected, never normalized);
 7. EIP-191 personal_sign recovery over the 32 link bytes defines a point, else unrecoverable;
 8. its address equals the normalized ledger_signer, else signer_mismatch."""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402

# the core's identifier_normalization whitespace set (MANIFEST identifier_normalization step 1), and no others
_WS = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680" + "".join(chr(c) for c in range(0x2000, 0x200B)) + "\u2028\u2029\u202f\u205f\u3000"
_HEX_RE = {32: re.compile(r"\A0x[0-9a-f]{64}\Z"), 20: re.compile(r"\A0x[0-9a-f]{40}\Z")}
_SIG_RE = re.compile(r"\A0x[0-9a-fA-F]{130}\Z")
SEQ_MAX = 2 ** 53 - 1
# the reject-reason closure is pinned HERE, not derived from MANIFEST.json (the core's convention): a fork that drops a class goes red
REJECT_REASONS = ("malformed_input", "unsupported_link_version", "malformed_signature", "non_canonical_s", "unrecoverable", "signer_mismatch")
LINK_VERSION = 1


def norm_hex(x, nbytes):
    """-> the normalized 0x-hex string, or None if x is not of that form after strip + lowercase."""
    if not isinstance(x, str):
        return None
    y = x.strip(_WS).lower()
    return y if _HEX_RE[nbytes].match(y) else None


def link(artifact_digest, prev_digest, seq):
    a = bytes.fromhex(artifact_digest[2:]); p = bytes.fromhex(prev_digest[2:]) if prev_digest else bytes(32)
    return keccak256(a + p + int(seq).to_bytes(8, "big"))


def check(inp, mut=None):
    """mut names a one-site broken verifier (MUTANTS); None is the profile."""
    if not isinstance(inp, dict) or any(k not in inp for k in ("artifact_digest", "seq", "countersignature", "ledger_signer")):
        return "reject", "malformed_input"
    if mut == "no_whitespace_strip":
        nh = lambda x, n: x.lower() if isinstance(x, str) and _HEX_RE[n].match(x.lower()) else None
    else:
        nh = norm_hex
    art = nh(inp["artifact_digest"], 32)
    prev = inp.get("prev_digest")
    prevn = None if prev is None else nh(prev, 32)
    signer = nh(inp["ledger_signer"], 20)
    seq = inp["seq"]
    lo = 0 if mut == "seq_zero_allowed" else 1
    seq_ok = isinstance(seq, int) and not isinstance(seq, bool) and lo <= seq <= SEQ_MAX
    if mut == "no_seq_type_check":
        try:
            seq = int(seq); seq_ok = lo <= seq <= SEQ_MAX
        except (TypeError, ValueError):
            seq_ok = False
    if art is None or (prev is not None and prevn is None) or signer is None or not seq_ok:
        return "reject", "malformed_input"
    lv = inp.get("link_version", LINK_VERSION)
    if mut != "link_version_ignored" and not (isinstance(lv, int) and not isinstance(lv, bool) and lv == LINK_VERSION):
        return "reject", "unsupported_link_version"
    sig_field = inp["countersignature"]
    if mut == "lenient_signature_parsing" and isinstance(sig_field, str):
        sig_field = "0x" + "".join(sig_field.split()).lower().removeprefix("0x")
    if not (isinstance(sig_field, str) and _SIG_RE.match(sig_field)):
        return "reject", "malformed_signature"
    sig = bytes.fromhex(sig_field[2:])
    v = sig[64]
    if mut == "v_normalized_mod_2":
        v = 27 + (v - 27) % 2
    if v not in (27, 28):
        return "reject", "malformed_signature"
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if s > S.N // 2:
        if mut == "high_s_normalized":
            s, v = S.N - s, 55 - v   # "fix" the encoding instead of refusing it, as many libraries do
        elif mut != "no_low_s_check":
            return "reject", "non_canonical_s"
    L = link(art, None if mut == "link_ignores_prev" else prevn, 1 if mut == "link_ignores_seq" else seq)
    Q = S.recover(L if mut == "recover_over_raw_digest" else S.personal_sign_hash(L), r, s, v - 27)
    if Q is None:
        return "reject", "unrecoverable"
    want = "0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6" if mut == "hardcoded_tersign_signer" else signer
    if S.address(Q) != want:
        return "reject", "signer_mismatch"
    return "valid", None


MUTANTS = {   # each is a plausible broken verifier; the suite must fail it on the named vector
    "no_low_s_check": "cn3-high-s-malleated-live-signature",
    "high_s_normalized": "cn3-high-s-malleated-live-signature",
    "recover_over_raw_digest": "cn4-raw-digest-signature-no-eip191-prefix",
    "link_ignores_seq": "cn1-signature-moved-to-another-seq",
    "link_ignores_prev": "cp4-live-seq2-link-countersignature",
    "hardcoded_tersign_signer": "cp2-test-key-accepting-twin",
    "v_normalized_mod_2": "cn6-recovery-byte-out-of-range",
    "no_seq_type_check": "cn10-seq-wrong-type-string",
    "seq_zero_allowed": "cn25-seq-zero",
    "lenient_signature_parsing": "cn14-signature-missing-0x-prefix",
    "link_version_ignored": "cn27-unsupported-link-version",
    "no_whitespace_strip": "cp5-digest-trailing-newline-normalized",
}
MANIFEST = os.path.join(HERE, "MANIFEST.json")


def load_set():
    """-> (vectors by id, problems). The runner reads MANIFEST.json, never a directory listing."""
    m = json.load(open(MANIFEST))
    vecs, problems = {}, []
    listed = {e["file"] for e in m["vectors"]}
    on_disk = {os.path.basename(f) for f in glob.glob(os.path.join(HERE, "vectors", "*.json"))}
    problems += [f"on disk, not in MANIFEST: {f}" for f in sorted(on_disk - listed)]
    problems += [f"in MANIFEST, not on disk: {f}" for f in sorted(listed - on_disk)]
    for e in m["vectors"]:
        if e["file"] not in on_disk:
            continue
        v = json.load(open(os.path.join(HERE, "vectors", e["file"])))
        if (v["expect"], v["kind"]) != (e["expect"], e["kind"]):
            problems.append(f"{e['file']}: MANIFEST expect/kind disagrees with the vector")
        if e.get("origin", {}).get("class") not in ORIGIN_CLASSES:
            problems.append(f"{e['file']}: origin.class not in {ORIGIN_CLASSES}")
        vecs[v["id"]] = v
    if not vecs:
        problems.append("empty vector set")
    kinds = {}
    for v in vecs.values():
        kinds.setdefault(v["kind"], set()).add(v["expect"])
    problems += [f"kind {k} is one-sided ({sorted(x)})" for k, x in kinds.items() if x != {"valid", "reject"}]
    exercised = {v.get("reject_reason") for v in vecs.values() if v["expect"] == "reject"}
    if tuple(m.get("reject_reasons", ())) != REJECT_REASONS:
        problems.append(f"MANIFEST reject_reasons {m.get('reject_reasons')} != the runner's pinned closure {REJECT_REASONS}")
    problems += [f"reject reason never exercised: {r}" for r in REJECT_REASONS if r not in exercised]
    problems += [f"vector uses an undeclared reason: {r}" for r in sorted(exercised - set(REJECT_REASONS))]
    problems += [f"mutant {n} names a missing vector {vid}" for n, vid in MUTANTS.items() if vid not in vecs]
    return vecs, problems


ORIGIN_CLASSES = ("synthetic", "live-ledger", "live-ledger-derived", "contributed")


def mutants():
    vecs, problems = load_set()
    bad = len(problems)
    for p in problems:
        print("SET  ", p)
    for name, vid in MUTANTS.items():
        if vid not in vecs:
            continue
        v = vecs[vid]; got, why = check(v["input"], name)
        killed = not (got == v["expect"] and why == v.get("reject_reason"))
        bad += not killed
        print(f"{'killed  ' if killed else 'SURVIVED'} mutant {name:26s} by {vid} (mutant says {got}{' '+why if why else ''})")
    print(f"{len(MUTANTS) - bad}/{len(MUTANTS)} mutants killed" if not problems else "set problems above")
    return 1 if bad else 0


def main():
    if "--mutants" in sys.argv:
        return mutants()
    vecs, problems = load_set()
    bad = len(problems)
    for p in problems:
        print("SET  ", p)
    for vid in sorted(vecs, key=lambda i: (i[:2], int("".join(c for c in i.split("-")[0] if c.isdigit()) or 0))):
        v = vecs[vid]; got, why = check(v["input"])
        ok = got == v["expect"] and (why == v.get("reject_reason"))
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {v['id']:48s} expect={v['expect']:6s} got={got}{' ('+why+')' if why else ''}")
    print(f"{len(vecs) - (bad - len(problems))}/{len(vecs)} crypto-profile vectors match" + ("" if not problems else f"; {len(problems)} set problem(s)"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
