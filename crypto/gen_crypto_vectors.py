#!/usr/bin/env python3
"""Generates every crypto-profile vector and crypto/MANIFEST.json, byte for byte. Stdlib only.
    python3 crypto/gen_crypto_vectors.py      (CI regenerates and requires byte-identical output)
Material: two live ledger records (cp1 genesis, cp4 seq 2) whose values are pinned below with their public endpoints; everything
else is derived from them, or signed by the published TEST key (never a real signer) with a fixed nonce, both derived in-file."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402
from verify_crypto import link, SEQ_MAX, REJECT_REASONS  # noqa: E402

# ---- live material (unaltered)
SIGNER = "0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"
G_ART = "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4"
G_SIG = "0xfccc1add7301c688e03311ff04b9aecac4f0d81a468fc95128b24aa0c8aff2bf3b148181befffc6dbe739b1991d936cd434a2fa2bcb8ea1f49a06b8f7a3fff1d1c"
S2_ART = "0x89dbfc8c52bd5fa4ed5e879915518f9729cfbd74d9ab020e569eeffd881a4f1c"
S2_SIG = "0x0ede826d797ad3e0601d213ebfdfa570b1ca9f74abe826d3c5e3479e1f93d38e13da2f7ffeb7760312024b4d6d0f0c541f42443aef75ea529fa19fd97791c31f1b"
S2_ANCHOR_SUBJECT = "0xddc12b814c54daa839b1e9e66820d7d28c5bbf254eec0004de2f9d8ba98331ae"
PROV = {
    "cp1": {"ledger": "https://tersign.ai", "record": "curl https://tersign.ai/v1/genesis",
            "verify": f"curl https://tersign.ai/v1/receipts/{G_ART}/verify", "countersignature": G_SIG, "ledger_signer": SIGNER},
    "cp4": {"ledger": "https://tersign.ai", "verify": f"curl https://tersign.ai/v1/receipts/{S2_ART}/verify",
            "seq": 2, "prev_digest": G_ART, "countersignature": S2_SIG, "ledger_signer": SIGNER},
}
# ---- published test key and fixed nonce (test vectors only)
TEST_KEY_DERIVATION = 'keccak256("evidence-record-conformance crypto-profile test key v1") mod n'
TEST_NONCE_DERIVATION = 'keccak256("fixed nonce, test vectors only") mod n'
PRIV = int.from_bytes(keccak256(b"evidence-record-conformance crypto-profile test key v1"), "big") % S.N
K = int.from_bytes(keccak256(b"fixed nonce, test vectors only"), "big") % S.N
TEST_ADDR = S.address(S._mul(PRIV, S.G))


def sighex(r, s, rec):
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + rec]).hex()


def with_sig(sig, r=None, s=None, v=None):
    b = bytearray(bytes.fromhex(sig[2:]))
    if r is not None: b[:32] = r.to_bytes(32, "big")
    if s is not None: b[32:64] = s.to_bytes(32, "big")
    if v is not None: b[64] = v
    return "0x" + bytes(b).hex()


def off_curve_r():
    x = 1
    while True:
        y2 = (pow(x, 3, S.P) + 7) % S.P
        if pow(y2, (S.P - 1) // 2, S.P) != 1:
            return x
        x += 1


def main():
    base = {"artifact_digest": G_ART, "prev_digest": None, "seq": 1, "countersignature": G_SIG, "ledger_signer": SIGNER}
    s2 = {"artifact_digest": S2_ART, "prev_digest": G_ART, "seq": 2, "countersignature": S2_SIG, "ledger_signer": SIGNER}
    L1 = link(G_ART, None, 1)
    t_sig = sighex(*S.sign(S.personal_sign_hash(L1), PRIV, K))
    raw_sig = sighex(*S.sign(L1, PRIV, K))
    Lmax = link(G_ART, None, SEQ_MAX)
    max_sig = sighex(*S.sign(S.personal_sign_hash(Lmax), PRIV, K))
    gr = int(G_SIG[2:66], 16); gs = int(G_SIG[66:130], 16)
    no_prev = {k: v for k, v in base.items() if k != "prev_digest"}
    ME = "@babyblueviper1"
    LD = lambda what: (ME, "live-ledger-derived", what)
    SYN = (ME, "synthetic", "inputs constructed in crypto/gen_crypto_vectors.py with the published test key")
    R1 = "@robertolocatelli81-dev's published reproduction (Noûs), PR #11 issuecomment-5905183087; written here on cp1's values"
    R2 = "@robertolocatelli81-dev's published reproduction (Noûs), PR #11 issuecomment-5907121036; written here on cp1's values"
    C1 = (ME, "contributed", R1); C2 = (ME, "contributed", R2)
    V = [  # id, expect, reason, input, (author, class, source)
        ("cp1-live-genesis-link-countersignature", "valid", None, base, (ME, "live-ledger", "the ledger's counter-signature over the genesis link, unaltered; the vector's provenance block names the public endpoints")),
        ("cp2-test-key-accepting-twin", "valid", None, {**base, "countersignature": t_sig, "ledger_signer": TEST_ADDR}, SYN),
        ("cp3-prev-digest-absent-key-equals-null", "valid", None, no_prev, LD("cp1 with the prev_digest key omitted")),
        ("cp4-live-seq2-link-countersignature", "valid", None, s2, (ME, "live-ledger", "the ledger's counter-signature over the seq-2 link, unaltered; the vector's provenance block names the public endpoint")),
        ("cp5-digest-trailing-newline-normalized", "valid", None, {**base, "artifact_digest": G_ART + "\n"}, C2),
        ("cp6-ledger-signer-trailing-newline-normalized", "valid", None, {**base, "ledger_signer": SIGNER + "\n"}, C2),
        ("cp7-digest-uppercase-0X-normalized", "valid", None, {**base, "artifact_digest": "0X" + G_ART[2:].upper()}, C2),
        ("cp8-explicit-link-version-1", "valid", None, {**base, "link_version": 1}, LD("cp1 with link_version 1 carried explicitly")),
        ("cp9-seq-max-test-key", "valid", None, {**base, "seq": SEQ_MAX, "countersignature": max_sig, "ledger_signer": TEST_ADDR}, SYN),
        ("cn1-signature-moved-to-another-seq", "reject", "signer_mismatch", {**base, "seq": 2}, LD("cp1's signature moved to seq 2")),
        ("cn2-foreign-signer-claims-ledger", "reject", "signer_mismatch", {**base, "countersignature": t_sig}, SYN),
        ("cn3-high-s-malleated-live-signature", "reject", "non_canonical_s", {**base, "countersignature": with_sig(G_SIG, s=S.N - gs, v=55 - int(G_SIG[130:], 16))}, LD("cp1's signature malleated to s' = n - s, v flipped")),
        ("cn4-raw-digest-signature-no-eip191-prefix", "reject", "signer_mismatch", {**base, "countersignature": raw_sig, "ledger_signer": TEST_ADDR}, SYN),
        ("cn5-truncated-64-byte-signature", "reject", "malformed_signature", {**base, "countersignature": G_SIG[:130]}, LD("cp1's signature with the recovery byte dropped")),
        ("cn6-recovery-byte-out-of-range", "reject", "malformed_signature", {**base, "countersignature": with_sig(G_SIG, v=29)}, LD("cp1's signature with v = 29")),
        ("cn7-non-hex-artifact-digest", "reject", "malformed_input", {**base, "artifact_digest": "0xnot-hex-at-all"}, C1),
        ("cn8-negative-seq", "reject", "malformed_input", {**base, "seq": -1}, C1),
        ("cn9-seq-out-of-range", "reject", "malformed_input", {**base, "seq": 2 ** 64}, C1),
        ("cn10-seq-wrong-type-string", "reject", "malformed_input", {**base, "seq": "1"}, C1),
        ("cn11-seq-wrong-type-bool", "reject", "malformed_input", {**base, "seq": True}, C1),
        ("cn12-malformed-ledger-signer", "reject", "malformed_input", {**base, "ledger_signer": "0xabc"}, C1),
        ("cn13-malformed-prev-digest", "reject", "malformed_input", {**base, "prev_digest": "0xnot-a-real-digest"}, C1),
        ("cn14-signature-missing-0x-prefix", "reject", "malformed_signature", {**base, "countersignature": G_SIG[2:]}, C1),
        ("cn15-signature-embedded-whitespace", "reject", "malformed_signature", {**base, "countersignature": G_SIG[:10] + " " + G_SIG[10:]}, C1),
        ("cn16-signature-trailing-newline", "reject", "malformed_signature", {**base, "countersignature": G_SIG + "\n"}, C2),
        ("cn17-digest-bom-padded", "reject", "malformed_input", {**base, "artifact_digest": G_ART + "﻿"}, LD("cp1's digest followed by U+FEFF")),
        ("cn18-signature-uppercase-0X-prefix", "reject", "malformed_signature", {**base, "countersignature": "0X" + G_SIG[2:]}, C2),
        ("cn19-moved-predecessor-live-seq2", "reject", "signer_mismatch", {**s2, "prev_digest": S2_ANCHOR_SUBJECT}, LD("cp4 with prev_digest replaced by that record's anchor subjectDigest")),
        ("cn20-unrecoverable-r-off-curve", "reject", "unrecoverable", {**base, "countersignature": with_sig(G_SIG, r=off_curve_r())}, LD("cp1's s and v with r replaced by the smallest x that is not on the curve")),
        ("cn21-recovery-byte-zero", "reject", "malformed_signature", {**base, "countersignature": with_sig(G_SIG, v=0)}, LD("cp1's signature with v = 0")),
        ("cn22-recovery-byte-one", "reject", "malformed_signature", {**base, "countersignature": with_sig(G_SIG, v=1)}, LD("cp1's signature with v = 1")),
        ("cn23-low-s-boundary-accepted-then-mismatch", "reject", "signer_mismatch", {**base, "countersignature": with_sig(G_SIG, s=S.N // 2)}, LD("cp1's r with s = floor(n/2)")),
        ("cn24-low-s-boundary-plus-one", "reject", "non_canonical_s", {**base, "countersignature": with_sig(G_SIG, s=S.N // 2 + 1)}, LD("cp1's r with s = floor(n/2) + 1")),
        ("cn25-seq-zero", "reject", "malformed_input", {**base, "seq": 0}, LD("cp1 with seq 0")),
        ("cn26-seq-above-2-53", "reject", "malformed_input", {**base, "seq": SEQ_MAX + 1}, LD("cp1 with seq 2**53")),
        ("cn27-unsupported-link-version", "reject", "unsupported_link_version", {**base, "link_version": 2}, LD("cp1 with link_version 2")),
        ("cn28-link-version-string", "reject", "unsupported_link_version", {**base, "link_version": "1"}, LD('cp1 with link_version "1"')),
    ]
    os.makedirs(os.path.join(HERE, "vectors"), exist_ok=True)
    for f in os.listdir(os.path.join(HERE, "vectors")):
        if f.endswith(".json"):
            os.remove(os.path.join(HERE, "vectors", f))
    entries = []
    for vid, expect, reason, inp, (author, cls, source) in V:
        v = {"id": vid, "kind": "countersignature", "expect": expect}
        if reason:
            v["reject_reason"] = reason
        v["description"] = DESC[vid]
        v["input"] = inp
        key = vid.split("-")[0]
        if cls == "live-ledger":
            v["provenance"] = PROV[key]
        with open(os.path.join(HERE, "vectors", vid + ".json"), "w") as fh:
            fh.write(json.dumps(v, indent=2) + "\n")
        entries.append({"file": vid + ".json", "kind": "countersignature", "expect": expect, "author": author,
                        "origin": {"class": cls, "source": source}})
    manifest = {
        "profile": "crypto (secp256k1 personal_sign counter-signature recovery over chain links)",
        "runner": "crypto/verify_crypto.py",
        "generator": "crypto/gen_crypto_vectors.py",
        "licence": "Apache-2.0, as the repository (LICENSE)",
        "link_version": 1,
        "link_recipe": {"1": "keccak256(artifact_digest || prev_digest, or 32 zero bytes when absent || uint64_be(seq)), the core chain_link"},
        "link_version_rule": "an input may carry link_version; absent means 1; any value other than the integer 1 rejects as unsupported_link_version",
        "field_domain": "artifact_digest, prev_digest and ledger_signer: strip leading/trailing Unicode White_Space characters (the core's identifier_normalization set) and lowercase, then exactly 0x + 64 hex (digests) or 0x + 40 hex (signer); seq: an integer token in [1, 2**53 - 1]; countersignature: matched whole and unnormalized, exactly 0x + 130 hex digits, v in {27, 28}",
        "reject_reasons": list(REJECT_REASONS),
        "set_rules": "the runner reads this file, not a directory listing, and fails on a file on disk but not listed (or the reverse), an empty set, a one-sided kind, a declared reason no vector exercises, or a reason not declared",
        "test_key_address": TEST_ADDR,
        "test_key_derivation": TEST_KEY_DERIVATION,
        "test_nonce_derivation": TEST_NONCE_DERIVATION,
        "vector_provenance": "as the core's vector_provenance: author = the GitHub account that authored the commit adding the vector; origin.class in (synthetic, live-ledger, live-ledger-derived, contributed); live-ledger vectors carry a provenance block naming the public endpoint",
        "vectors": entries,
    }
    with open(os.path.join(HERE, "MANIFEST.json"), "w") as fh:
        fh.write(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(V)} vectors + MANIFEST.json")


DESC = {
 "cp1-live-genesis-link-countersignature": "Live: the tersign ledger's counter-signature over the genesis chain link (p1 provenance, link recomputed exactly as p4). personal_sign recovery returns the pinned ledger_signer.",
 "cn10-seq-wrong-type-string": "seq is the string \"1\", not an integer. int(seq) silently coerces a well-formed numeral to the same value a real int would produce -- a verifier that does that accepts a field of the wrong declared type.",
 "cn12-malformed-ledger-signer": "ledger_signer is not a well-formed 20-byte 0x-address (too short). Its form must be checked before it is used as an equality target, not merely strip()+lower()ed.",
 "cn2-foreign-signer-claims-ledger": "A different key (the published test key) signs the genuine link, but the record claims the ledger as signer. Recovery returns the test key.",
 "cp2-test-key-accepting-twin": "Accepting twin of cn4: a published TEST key's personal_sign over the same link, declared signer = that key. A runner that hard-codes the tersign signer instead of reading ledger_signer fails here.",
 "cn1-signature-moved-to-another-seq": "The live counter-signature presented for the same artifact at seq 2. The link commits to position, so the recovered key is not the ledger's: a counter-signature cannot be moved along the chain.",
 "cn15-signature-embedded-whitespace": "countersignature has a stray space inside the hex body. A verifier that strips/cleans the field before parsing (rather than requiring the exact declared form) can be tricked into accepting a signature encoding that was never declared valid.",
 "cn8-negative-seq": "seq is negative. int.to_bytes(8, 'big') raises OverflowError on a negative int unless the field's declared range (uint64) is checked first.",
 "cn13-malformed-prev-digest": "prev_digest is present but not a well-formed 32-byte 0x-digest. An absent prev_digest (missing key or null) means genesis; a present-but-malformed one is a different, rejectable case -- it must not be silently treated as absent.",
 "cn4-raw-digest-signature-no-eip191-prefix": "The test key signs the raw 32-byte link without the EIP-191 personal_sign prefix; the record declares the test key. Recovering over the prefixed hash (the profile's domain) returns a different key. A runner that recovers over the raw digest accepts it: the domain must be pinned.",
 "cn3-high-s-malleated-live-signature": "The live signature malleated to s' = n - s with v flipped. It RECOVERS TO THE SAME LEDGER SIGNER, so a runner that only compares recovered addresses accepts it. EIP-2 low-s rejects it: two distinct signature byte strings must not both verify one link.",
 "cn16-signature-trailing-newline": "countersignature is otherwise cp1's genuine, recoverable value with a trailing newline appended. In Python's re module, unqualified $ matches at end-of-string OR immediately before a trailing newline, so a naive ^...$ shape check silently accepts this. The runner must anchor with \\A...\\Z (or an explicit no-trailing-newline check), not ^...$.",
 "cn5-truncated-64-byte-signature": "The live signature with its recovery byte dropped (64 bytes). No key is recovered from an incomplete signature; it must not be treated as unverifiable-but-fine.",
 "cn11-seq-wrong-type-bool": "seq is the boolean True, not an integer. bool is an int subclass in Python; a verifier using isinstance(seq, int) alone accepts it.",
 "cp3-prev-digest-absent-key-equals-null": "prev_digest key is omitted entirely (not merely null). Must resolve identically to cp1 (null): both declare genesis, both recompute the same link, both verify against the same live counter-signature.",
 "cn7-non-hex-artifact-digest": "artifact_digest is not valid 32-byte hex. A verifier that reaches for bytes.fromhex() unguarded raises instead of rejecting -- a crash is not a reject.",
 "cn9-seq-out-of-range": "seq is >= 2**64, outside the declared uint64 range. int.to_bytes(8, 'big') raises OverflowError rather than the verifier rejecting cleanly.",
 "cn14-signature-missing-0x-prefix": "countersignature is the correct 130 hex digits but without the 0x prefix. This is a malformed *signature field*, not a malformed_input -- the distinction pins that field-shape checks for the other declared fields happen before signature parsing, while the signature's own shape is still judged under malformed_signature.",
 "cn6-recovery-byte-out-of-range": "The live signature with v = 29. personal_sign signatures carry v in {27, 28}; any other value is malformed, not silently normalized.",
 "cp4-live-seq2-link-countersignature": "Live, non-genesis: the ledger's counter-signature over the seq-2 chain link (artifact 0x89db...4f1c, predecessor the genesis digest). Recovery over the link with a real predecessor and seq > 1 returns the pinned ledger_signer. Provenance block names the public endpoint.",
 "cp5-digest-trailing-newline-normalized": "cp1 with a trailing newline on artifact_digest. Digests are normalized as the core's identifier_normalization does (strip the Unicode White_Space set, then lowercase) before the shape check, so this is cp1's link and it is valid. Accepting twin of cn17: an engine that defends the whitespace class by refusing padded digests fails here.",
 "cp6-ledger-signer-trailing-newline-normalized": "cp1 with a trailing newline on ledger_signer: normalized to the same address, valid. Pins strip-then-shape for the signer (Tersign's merge item 3, @robertolocatelli81-dev's reading).",
 "cp7-digest-uppercase-0X-normalized": "cp1 with artifact_digest written 0X + upper-case hex. Lowercasing is part of normalization for digests and the signer, so this is cp1's link and it is valid. The countersignature is NOT normalized: cn18 pins 0X there as malformed.",
 "cp8-explicit-link-version-1": "cp1 with link_version: 1 carried explicitly. Absent and 1 are the same recipe (MANIFEST link_version); this is valid. Accepting twin of cn27/cn28.",
 "cp9-seq-max-test-key": "The top of the seq domain: seq = 2**53 - 1 (the largest integer every JSON engine carries exactly), signed by the published test key over that link. Valid. Boundary twin of cn26.",
 "cn17-digest-bom-padded": "artifact_digest is cp1's digest followed by U+FEFF. U+FEFF is a format character without the White_Space property, so normalization does not strip it (the core's n52 rule) and the digest does not parse: malformed_input.",
 "cn18-signature-uppercase-0X-prefix": "countersignature is cp1's genuine value with the prefix written 0X. The signature is matched whole and unnormalized (exactly 0x + 130 hex): malformed_signature. Tersign's own verifiers refuse it.",
 "cn19-moved-predecessor-live-seq2": "cp4's genuine seq-2 signature presented over a link whose prev_digest is another real ledger digest (that record's anchor subjectDigest) instead of the genesis digest. The link commits to its predecessor, so recovery returns a different address: signer_mismatch.",
 "cn20-unrecoverable-r-off-curve": "A well-formed, low-s signature whose r is not the x-coordinate of any curve point. Recovery defines no public key: unrecoverable. A verifier that skips the curve check derives a garbage point instead of refusing.",
 "cn21-recovery-byte-zero": "cp1's signature with v = 0 (the raw recovery id, as some libraries emit it). The profile's v is 27 or 28 only, never normalized: malformed_signature.",
 "cn22-recovery-byte-one": "cp1's signature with v = 1: malformed_signature, for the same reason as cn21.",
 "cn23-low-s-boundary-accepted-then-mismatch": "cp1's r with s = floor(n/2), the largest canonical s. It passes the low-s check (EIP-2: s <= n/2) and fails later, at signer_mismatch. The reason is the point: an off-by-one verifier that refuses s = n/2 reports non_canonical_s here.",
 "cn24-low-s-boundary-plus-one": "cp1's r with s = floor(n/2) + 1, the smallest non-canonical s: non_canonical_s, before any recovery. Twin of cn23 across the boundary.",
 "cn25-seq-zero": "cp1 with seq = 0. The core's sequence starts at 1, so 0 is outside the domain [1, 2**53 - 1]: malformed_input.",
 "cn26-seq-above-2-53": "seq = 2**53, one past the domain: malformed_input. Above 2**53 a JSON double can no longer tell adjacent integers apart, so two engines would disagree on which link was signed.",
 "cn27-unsupported-link-version": "cp1 with link_version: 2. Only recipe 1 exists; any other value rejects on its own reason, unsupported_link_version, rather than being read as 1.",
 "cn28-link-version-string": "cp1 with link_version: \"1\". The version is an integer token; the string is not 1: unsupported_link_version."
}

if __name__ == "__main__":
    main()
