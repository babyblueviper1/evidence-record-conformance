#!/usr/bin/env python3
"""Crypto-profile runner (counter-signature recovery over chain links). Stdlib only + the suite's keccak.py.
    python3 crypto/verify_crypto.py            -> runs crypto/vectors/*.json, exit 0 iff every verdict and reject reason matches
Check, per vector: link = keccak256(artifact_digest || prev_digest (or 32 zero bytes) || seq_uint64_be)  [the core chain_link];
the 65-byte counter-signature r||s||v must be well formed (v in {27,28}), low-s (EIP-2: s <= n/2), and secp256k1 personal_sign
(EIP-191 0x45) recovery over the 32 link bytes must return the declared signer (0x-address, compared after strip + lowercase).
Reject reasons: malformed_signature, non_canonical_s, unrecoverable, signer_mismatch, malformed_input.
malformed_input covers artifact_digest / prev_digest / seq / ledger_signer: each is checked for its exact
declared form (32-byte 0x-hex digest, 0x-hex 20-byte address, seq a real int in [0, 2**64), never a str/
float/bool) before the signature is even parsed. An absent prev_digest (key missing or null) is not
malformed -- both mean "genesis", 32 zero bytes. malformed_signature stays scoped to the signature field
itself: exactly "0x" followed by 130 hex digits, no surrounding whitespace, no missing prefix -- a
leniently-parsed signature (stray whitespace, a dropped "0x") must not silently recover and pass."""
import glob, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402

_DIGEST_RE = {32: re.compile(r"\A0[xX][0-9a-fA-F]{64}\Z"), 20: re.compile(r"\A0[xX][0-9a-fA-F]{40}\Z")}
_SIG_RE = re.compile(r"\A0[xX][0-9a-fA-F]{130}\Z")


def _is_hex_of(x, nbytes):
    return isinstance(x, str) and bool(_DIGEST_RE[nbytes].match(x))


def link(artifact_digest, prev_digest, seq):
    a = bytes.fromhex(artifact_digest[2:]); p = bytes.fromhex(prev_digest[2:]) if prev_digest else bytes(32)
    return keccak256(a + p + int(seq).to_bytes(8, "big"))


def check(inp):
    for k in ("artifact_digest", "seq", "countersignature", "ledger_signer"):
        if k not in inp:
            return "reject", "malformed_input"
    if not _is_hex_of(inp["artifact_digest"], 32):
        return "reject", "malformed_input"
    prev_digest = inp.get("prev_digest")
    if prev_digest is not None and not _is_hex_of(prev_digest, 32):
        return "reject", "malformed_input"
    seq = inp["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or not (0 <= seq < 2 ** 64):
        return "reject", "malformed_input"
    if not _is_hex_of(inp["ledger_signer"], 20):
        return "reject", "malformed_input"
    sig_field = inp["countersignature"]
    if not (isinstance(sig_field, str) and _SIG_RE.match(sig_field)):
        return "reject", "malformed_signature"
    sig = bytes.fromhex(sig_field[2:])
    if sig[64] not in (27, 28):
        return "reject", "malformed_signature"
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if s > S.N // 2:
        return "reject", "non_canonical_s"
    Q = S.recover(S.personal_sign_hash(link(inp["artifact_digest"], prev_digest, seq)), r, s, sig[64] - 27)
    if Q is None:
        return "reject", "unrecoverable"
    if S.address(Q) != inp["ledger_signer"].strip().lower():
        return "reject", "signer_mismatch"
    return "valid", None


MUTANTS = {   # each is a plausible broken verifier; the suite must fail it on the named vector
    "no_low_s_check": "cn3-high-s-malleated-live-signature",
    "recover_over_raw_digest": "cn4-raw-digest-signature-no-eip191-prefix",
    "link_ignores_seq": "cn1-signature-moved-to-another-seq",
    "hardcoded_tersign_signer": "cp2-test-key-accepting-twin",
    "v_normalized_mod_2": "cn6-recovery-byte-out-of-range",
    "high_s_normalized": "cn3-high-s-malleated-live-signature",
    "no_seq_type_check": "cn10-seq-wrong-type-string",
    "lenient_signature_parsing": "cn14-signature-missing-0x-prefix",
}


def mutant_check(name, inp):
    if name == "lenient_signature_parsing":
        sig = bytes.fromhex(inp["countersignature"].strip().removeprefix("0x"))
    else:
        sig_field = inp["countersignature"]
        if not (isinstance(sig_field, str) and _SIG_RE.match(sig_field)):
            return "reject", "malformed_signature"
        sig = bytes.fromhex(sig_field[2:])
    if len(sig) != 65:
        return "reject", "malformed_signature"
    v = sig[64]
    if name == "v_normalized_mod_2":
        v = 27 + (v - 27) % 2
    elif v not in (27, 28):
        return "reject", "malformed_signature"
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if name == "high_s_normalized" and s > S.N // 2:
        s, v = S.N - s, 55 - v   # "fix" the encoding instead of refusing it, as many libraries do
    elif name != "no_low_s_check" and s > S.N // 2:
        return "reject", "non_canonical_s"
    L = link(inp["artifact_digest"], inp.get("prev_digest"), 1 if name == "link_ignores_seq" else inp["seq"])
    h = L if name == "recover_over_raw_digest" else S.personal_sign_hash(L)
    Q = S.recover(h, r, s, v - 27)
    if Q is None:
        return "reject", "unrecoverable"
    want = "0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6" if name == "hardcoded_tersign_signer" else inp["ledger_signer"].strip().lower()
    return ("valid", None) if S.address(Q) == want else ("reject", "signer_mismatch")


def mutants():
    vecs = {json.load(open(f))["id"]: json.load(open(f)) for f in glob.glob(os.path.join(HERE, "vectors", "*.json"))}
    bad = 0
    for name, vid in MUTANTS.items():
        v = vecs[vid]; got, why = mutant_check(name, v["input"])
        killed = not (got == v["expect"] and why == v.get("reject_reason"))
        bad += not killed
        print(f"{'killed  ' if killed else 'SURVIVED'} mutant {name:26s} by {vid} (mutant says {got}{' '+why if why else ''})")
    return 1 if bad else 0


def main():
    if "--mutants" in sys.argv:
        return mutants()
    bad = 0; files = sorted(glob.glob(os.path.join(HERE, "vectors", "*.json")))
    for f in files:
        v = json.load(open(f)); got, why = check(v["input"])
        ok = got == v["expect"] and (why == v.get("reject_reason"))
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {v['id']:44s} expect={v['expect']:6s} got={got}{' ('+why+')' if why else ''}")
    print(f"{len(files) - bad}/{len(files)} crypto-profile vectors match")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
